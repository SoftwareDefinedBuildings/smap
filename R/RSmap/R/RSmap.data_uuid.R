RSmap.data_uuid <-
function(uuids, start, end, limit=-1){
  scipen <- .Options$scipen
  options(scipen=999)
  if(!is.numeric(start)){ stop("Invalid start time: must be numeric UTC milliseconds") }
  if(!is.numeric(end)){ stop("Invalid end time: must be numeric UTC milliseconds") }
  f <- function(uuid){
    query <- paste("select data in (", start
                   , ", ", end, ") "
                   , "limit ", format(limit, scientific=FALSE)
                   , " where uuid='", uuid, "'"
                   , sep="")   
    res <- .RSmap.postQuery(query)
    if(length(res)==0){
      write(paste("RSmap.data_uuid: no data found for uuid", uuid), stderr())
    } else {
      res <- .RSmap.refactorTSData(res)
      res$uuid = uuid
    }
    options(scipen=scipen)
    res
  }
  lapply(uuids, f)
}
