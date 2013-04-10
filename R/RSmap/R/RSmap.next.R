RSmap.next <-
function(where, ref, limit=1, streamlimit=10){
  query <- paste("select data after", ref
                 , "limit", limit
                 , "streamlimit", streamlimit
                 , "where", where)
  data <- .RSmap.postQuery(query)
  if (length(data)==0){  
    write(paste("RSmap.next: no data found after", ref, "where", where), stderr())
  } else {
    data <- .RSmap.refactorData(data)
  }
  data
}
