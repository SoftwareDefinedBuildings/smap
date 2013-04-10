library(RSmap)
RSmapClient("http://new.openbms.org/backend")

start <- as.numeric(strptime("3-29-2013", "%m-%d-%Y"))*1000
end <- as.numeric(strptime("3-31-2013", "%m-%d-%Y"))*1000

data <- RSmap.data("Metadata/Extra/Type = 'oat'", start, end)
tags <- RSmap.tags("Metadata/Extra/Type = 'oat'")
N <- length(data)

# returns a vector containing the min and max of the data
getExtents <- function(d){
  ex <- lapply(d, function(el){
    c(min(el$value), max(el$value))
  })
  ex <- unlist(ex)
  c(min(ex), max(ex))
}
ylim <- getExtents(data)

# convert to UTC seconds for R plot
time_UTC_sec <- data[[1]]$time/1000

# choose some pretty colors
col <- topo.colors(10)

# set up the plot and draw the first series
plot(time_UTC_sec
   , data[[1]]$value
   , xaxt="n"
   , type="l"
   , col=col[1]
   , ylim=ylim
   , xlab="Datetime"
   , ylab="Outside air temperature")

# format the x-axis to be the local time
axis.POSIXct(side=1, as.POSIXct(time_UTC_sec, origin="1970-01-01"),  format="%m-%d-%y")

# plot the rest of the series
for (i in 2:N){
  lines(data[[i]]$time/1000, data[[i]]$value, col=col[i])  
}

# extract the uuids from data and tags
uuids_data <- sapply(data, function(el){
  el$uuid
})
uuids_tags <- sapply(tags, function(el){
  el$uuid
})

# create a correspondence between uuids in tags/data
uuid_corr <- rep(NA, N)
for (i in 1:N){
  uuid_corr[i] <- which(uuids_tags==uuids_data[i])
}

# extract some metadata for a legend and render it
legend_labels <- rep(NA, length(N))
for (i in 1:N){
  t <- tags[[uuid_corr[i]]]
  legend_labels[i] <- paste(t$Metadata["SourceName"], " [", t$Properties["UnitofMeasure"], "]")
}
legend(start/1000, 45, legend_labels, lty=1, col=col, box.lwd = 0)
