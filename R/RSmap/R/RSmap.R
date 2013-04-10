RSmap <-
function(url, key=NULL, private=FALSE, timeout=50.0){

  keyStr <- paste(sapply(key, function(k){
    paste("key=",k,sep="")
  }), collapse="&")
  privateStr <- if(private) "&private=" else ""
  urlEnc <- paste(url, "/api/query?", keyStr, privateStr, sep="")

  .RSmap$data <- list(
    urlEnc=urlEnc,
    keyStr=keyStr,
    privateStr=privateStr,
    timeout=timeout
  )
}
