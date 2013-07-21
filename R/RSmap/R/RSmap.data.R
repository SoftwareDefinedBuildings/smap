RSmap.data <-
function(where, start, end, limit=10000, streamlimit=10){
  scipen <- .Options$scipen
  options(scipen=999)
  if(!is.numeric(start)){ stop("Invalid start time: must be numeric UTC milliseconds") }
  if(!is.numeric(end)){ stop("Invalid end time: must be numeric UTC milliseconds") }
  query <- paste("select data in (", start
                 , ",", end, ")"
                 , "limit", format(limit, scientific = FALSE)
                 , "streamlimit", format(streamlimit, scientific=FALSE)
                 , "where", where)
  data <- .RSmap.postQuery(query)
  if (length(data)==0){  
    write(paste("RSmap.data: no data found in (", start, ",", end, ") where", where), stderr())
  } else {
    data <- .RSmap.refactorData(data)
  }
  options(scipen=scipen)
  data
}
