\name{RSmap.data}
\alias{RSmap.data}
%- Also NEED an '\alias' for EACH other topic documented here.
\title{
RSmap.data
}
\description{
Load data for streams matching a particular where clause.

}
\usage{
RSmap.data(where, start, end, limit = 10000, streamlimit = 10)
}
%- maybe also 'usage' for other objects documented here.
\arguments{
  \item{where}{
    The ArchiverQuery selector for finding time series
}
  \item{start}{
    Query start time in UTC seconds (inclusive)
}
  \item{end}{
    Query end time in UTC seconds (exclusive)
}
  \item{limit}{
    The maximum number of points to retrieve per stream
%%     ~~Describe \code{limit} here~~
}
  \item{streamlimit}{
    The maximum number of streams to retrieve
%%     ~~Describe \code{streamlimit} here~~
}
}
\details{
%%  ~~ If necessary, more details than the description above ~~
}
\value{
Returns a list of data frames with properties \code{time}, \code{value}, and \code{uuid} containing the data corresponding to one of the uuids from the input.
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
## retrieve data
data <- RSmap.data("Metadata/Extra/Type = 'oat'", start, end)


## The function is currently defined as
function (where, start, end, limit = 10000, streamlimit = 10) 
{
    query <- paste("select data in (", start, ",", end, ")", 
        "limit", limit, "streamlimit", streamlimit, "where", 
        where)
    data <- RSmap.postQuery(query)
    if (length(data) == 0) {
        write(paste(".data: no data found in (", start, ",", 
            end, ") where", where), stderr())
    }
    else {
        data <- RSmap.refactorData(data)
    }
    data
  }
}
% Add one or more standard keywords, see file 'KEYWORDS' in the
% R documentation directory.
\keyword{ ~kwd1 }
\keyword{ ~kwd2 }% __ONLY ONE__ keyword per line
