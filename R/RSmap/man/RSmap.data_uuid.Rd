\name{RSmap.data_uuid}
\alias{RSmap.data_uuid}
%- Also NEED an '\alias' for EACH other topic documented here.
\title{
RSmap.data_uuid
}
\description{
    Low-level interface for loading a time range of data from a list of uuids. 
%%  ~~ A concise (1-5 lines) description of what the function does. ~~
}
\usage{
RSmap.data_uuid(uuids, start, end, limit)
}
%- maybe also 'usage' for other objects documented here.
\arguments{
  \item{uuids}{
    A list of stringified UUIDs
%%     ~~Describe \code{uuids} here~~
}
  \item{start}{
    The timestamp of the first record in seconds, inclusive
%%     ~~Describe \code{start} here~~
}
  \item{end}{
    The timestamp of the last record, exclusive
%%     ~~Describe \code{end} here~~
}
  \item{limit}{
    The maximum number of points to retrieve per stream
%%     ~~Describe \code{limit} here~~
}
}
\details{
%%  ~~ If necessary, more details than the description above ~~
}
\value{
Returns a list of data frames with properties \code{time}, \code{value}, and \code{uuid} containing the data corresponding to one of the uuids from the input.
%%  ~Describe the value returned
%%  If it is a LIST, use
%%  \item{comp1 }{Description of 'comp1'}
%%  \item{comp2 }{Description of 'comp2'}
%% ...
}
\references{
%% ~put references to the literature/web site here ~
}
\author{
Tyler Hoyt
}
\note{
%%  ~~further notes~~
}

%% ~Make other sections like Warning with \section{Warning }{....} ~

\seealso{
%% ~~objects to See Also as \code{\link{help}}, ~~~
}
\examples{
## define the connection
RSmap("http://new.openbms.org/backend")
## set start and end times
start <- as.numeric(strptime("3-30-2013", "\%m-\%d-\%Y"))*1000
end <- as.numeric(strptime("3-31-2013", "\%m-\%d-\%Y"))*1000
## define list of uuids
oat <- list("395005af-a42c-587f-9c46-860f3061ef0d",
         "9f091650-3973-5abd-b154-cee055714e59",
         "5d8f73d5-0596-5932-b92e-b80f030a3bf7",
         "d64e8d73-f0e9-5927-bbeb-8d45ab927ca5")
## retrieve data
data <- RSmap.data_uuid(oat, start, end)


## The function is currently defined as
function (uuids, start, end, limit) 
{
    f <- function(uuid) {
        query <- paste("select data in (", start, ", ", end, 
            ") ", "where uuid='", uuid, "'", sep = "")
        res <- RSmap.postQuery(query)
        if (length(res) == 0) {
            write(paste(".data_uuid: no data found for uuid", 
                uuid), stderr())
        }
        else {
            res <- RSmap.refactorTSData(res)
            res$uuid = uuid
        }
        res
    }
    lapply(uuids, f)
  }
}
% Add one or more standard keywords, see file 'KEYWORDS' in the
% R documentation directory.
\keyword{ ~kwd1 }
\keyword{ ~kwd2 }% __ONLY ONE__ keyword per line
