.RSmap <- new.env()
.RSmap.postQuery <-
function(query){
  r <- dynCurlReader()
  tryCatch({
    curlPerform(postfields=query
      , url=.RSmap$data$urlEnc
      , verbose=FALSE
      , writefunction=r$update
      , timeout=.RSmap$data$timeout)
  }, error = function(e) {
    stop('cURL error')
  })
  res <- r$value()
  if (res=="[]"){
    list()
  } else {
    fromJSON(res)
  }
}
.RSmap.refactorData <-
function(data){
  uuids <- sapply(data, function(el){ el$uuid })
  data <- lapply(data, function(el){ list(el) })
  data <- lapply(data, .RSmap.refactorTSData) 
  .RSmap.tagUuids(data, uuids)
}
.RSmap.refactorTSData <-
function(data){
  if (length(data)==0) return(data)
  d <- sapply(data, function(el){
    M <- length(el$Readings)
    i <- 1
    res <- data.frame(time=rep(NA, M), value=rep(NA, M))
    readings <- unlist(el$Readings)
    MM <- max(length(readings), 2)
    res$time <- readings[seq(1, MM, 2)]
    res$value <- readings[seq(2, MM, 2)]
    res
  })
  if (is.null(dim(d))){
    list()
  } else {
    d[,1]
  }
}
.RSmap.tagUuids <-
function(data, uuids){
  for (i in 1:length(uuids)){
    data[[i]]$uuid <- uuids[i]
  }
  data
}
