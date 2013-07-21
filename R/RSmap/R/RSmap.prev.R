RSmap.prev <-
function(where, ref, limit=1, streamlimit=10){
  scipen <- .Options$scipen
  options(scipen=999)
  if (!is.numeric(ref)) { stop("Invalid reference time: must be numeric") } 
  query <- paste("select data before", ref
                 , "limit", format(limit, scientific=FALSE)
                 , "streamlimit", format(streamlimit, scientific=FALSE)
                 , "where", where)
  data <- .RSmap.postQuery(query)
  if (length(data)==0){  
    write(paste("RSmap.prev: no data found before", ref, "where", where), stderr())
  } else {
    data <- .RSmap.refactorData(data)
  }
  options(scipen=scipen)
  data
}
