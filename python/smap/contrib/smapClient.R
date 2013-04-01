require(RCurl)
require(RJSONIO)

RSmapClient <- function(url, key=NULL, private=FALSE, timeout=50.0){

  keyStr <- paste(sapply(key, function(k){
    paste("key=",k,sep="")
  }), collapse="&")

  privateStr <- if(private) "&private=" else ""

  urlEnc <- paste(url, "/api/query?", keyStr, privateStr, sep="")

  postQuery <- function(query){
    r <- dynCurlReader()
    curlPerform(postfields=query
               , url=urlEnc
               , verbose=FALSE
               , writefunction=r$update
               , timeout=timeout)
    res <- r$value()
    if (res=="[]"){
      list()
    } else {
      fromJSON(res)
    }
  }
  
  refactorTSData <- function(data){
    if (length(data)==0) return(data)
    d <- sapply(data, function(el){
      M <- length(el$Readings)
      i <- 1
      res <- data.frame(time=rep(NA, M), value=rep(NA, M))
      for (val in el$Readings){
        res$time[i] = val[1]
        res$value[i] = val[2]
        i <- i + 1
      }
      res
    })
    d[,1]
  }  
 
  refactorData <- function(data){
    uuids <- sapply(data, function(el){ el$uuid })
    data <- lapply(data, function(el){ list(el) })
    data <- lapply(data, refactorTSData) 
    tagUuids(data, uuids)
  }

  tagUuids <- function(data, uuids){
    for (i in 1:length(uuids)){
      data[[i]]$uuid <- uuids[i]
    }
    data
  }
  
  c <- new.env()
  
  c$.latest <- function(where, limit=1, streamlimit=10){
    query <- paste("select data before now limit", limit
                   , "streamlimit", streamlimit
                   , "where", where)
    data <- postQuery(query)
    if (length(data)==0){  
      write(paste(".latest: no data found before now where", where), stderr())
    } else {
      data <- refactorData(data)
    }
    data
  }
  
  c$.prev <- function(where, ref, limit=1, streamlimit=10){
    query <- paste("select data before", ref
                   , "limit", limit
                   , "streamlimit", streamlimit
                   , "where", where)
    data <- postQuery(query)
    if (length(data)==0){  
      write(paste(".prev: no data found before", ref, "where", where), stderr())
    } else {
      data <- refactorData(data)
    }
    data
  }
  
  c$.next <- function(where, ref, limit=1, streamlimit=10){
    query <- paste("select data after", ref
                   , "limit", limit
                   , "streamlimit", streamlimit
                   , "where", where)
    data <- postQuery(query)
    if (length(data)==0){  
      write(paste(".next: no data found after", ref, "where", where), stderr())
    } else {
      data <- refactorData(data)
    }
    data
  }
  
  c$.data <- function(where, start, end, limit=10000, streamlimit=10){
    query <- paste("select data in (", start
                   , ",", end, ")"
                   , "limit", limit
                   , "streamlimit", streamlimit
                   , "where", where)
    data <- postQuery(query)
    if (length(data)==0){  
      write(paste(".data: no data found in (", start, ",", end, ") where", where), stderr())
    } else {
      data <- refactorData(data)
    }
    data
  }
  
  c$.data_uuid <- function(uuids, start, end, limit){
    f <- function(uuid){
      query <- paste("select data in (", start
                     , ", ", end, ") "
                     , "where uuid='", uuid, "'"
                     , sep="")   
      res <- postQuery(query)
      if(length(res)==0){
        write(paste(".data_uuid: no data found for uuid", uuid), stderr())
      } else {
        res <- refactorTSData(res)
        res$uuid = uuid
      }
      res
    }
    lapply(uuids, f)
  }
  
  c$.tags <- function(where){
    query <- paste("select * where ", where)
    res <- postQuery(query)
    if (length(res)==0) {
      write(paste(".tags: no tags found for streams where", where), stderr())
    }
    res
  }
    
  c
}
