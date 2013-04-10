RSmap.data_uuid <-
function(uuids, start, end, limit){
  f <- function(uuid){
    query <- paste("select data in (", start
                   , ", ", end, ") "
                   , "where uuid='", uuid, "'"
                   , sep="")   
    res <- .RSmap.postQuery(query)
    if(length(res)==0){
      write(paste("RSmap.data_uuid: no data found for uuid", uuid), stderr())
    } else {
      res <- .RSmap.refactorTSData(res)
      res$uuid = uuid
    }
    res
  }
  lapply(uuids, f)
}
