RSmap.latest <-
function(where, limit=1, streamlimit=10){
    query <- paste("select data before now limit", format(limit, scientific=FALSE)
                   , "streamlimit", format(streamlimit, scientific=FALSE)
                   , "where", where)
    data <- .RSmap.postQuery(query)
    if (length(data)==0){  
      write(paste("RSmap.latest: no data found before now where", where), stderr())
    } else {
      data <- .RSmap.refactorData(data)
    }
    data
  }
