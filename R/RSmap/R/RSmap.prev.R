RSmap.prev <-
function(where, ref, limit=1, streamlimit=10){
  query <- paste("select data before", ref
                 , "limit", limit
                 , "streamlimit", streamlimit
                 , "where", where)
  data <- .RSmap.postQuery(query)
  if (length(data)==0){  
    write(paste("RSmap.prev: no data found before", ref, "where", where), stderr())
  } else {
    data <- .RSmap.refactorData(data)
  }
  data
}
