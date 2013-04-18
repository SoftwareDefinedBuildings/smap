RSmap.data <-
function(where, start, end, limit=10000, streamlimit=10){
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
  data
}
