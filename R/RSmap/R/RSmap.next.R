RSmap.next <-
function(where, ref, limit=1, streamlimit=10){
  scipen <- .Options$scipen
  options(scipen=999)
  if(!is.numeric(ref)){ stop("Invalid reference time: must be numeric UTC milliseconds") }
  query <- paste("select data after", ref
                 , "limit", format(limit, scientific=FALSE)
                 , "streamlimit", format(streamlimit, scientific=FALSE)
                 , "where", where)
  data <- .RSmap.postQuery(query)
  if (length(data)==0){  
    write(paste("RSmap.next: no data found after", ref, "where", where), stderr())
  } else {
    data <- .RSmap.refactorData(data)
  }
  options(scipen=scipen)
  data
}
