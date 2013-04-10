RSmap.tags <-
function(where){
  query <- paste("select * where ", where)
  res <- .RSmap.postQuery(query)
  if (length(res)==0) {
    write(paste("RSmap.tags: no tags found for streams where", where), stderr())
  }
  res
}
