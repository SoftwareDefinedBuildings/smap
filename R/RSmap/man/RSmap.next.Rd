\name{RSmap.next}
\alias{RSmap.next}
%- Also NEED an '\alias' for EACH other topic documented here.
\title{
RSmap.next
}
\description{
    Load data after a reference time.
}
\usage{
RSmap.next(where, ref, limit = 1, streamlimit = 10)
}
%- maybe also 'usage' for other objects documented here.
\arguments{
  \item{where}{
    The ArchiverQuery selector for finding time series
}
  \item{ref}{
    Reference timestamp in UTC seconds after which to retrieve data
}
  \item{limit}{
    The maximum number of points to retrieve per stream
}
  \item{streamlimit}{
    The maximum number of streams to retrieve
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
RSmap("http://new.openbms.org/backend")
ref <- as.numeric(strptime("3-29-2013", "\%m-\%d-\%Y"))*1000
data <- RSmap.next("Metadata/Extra/Type = 'oat'", ref)

## The function is currently defined as
function (where, ref, limit = 1, streamlimit = 10) 
{
    query <- paste("select data after", ref, "limit", limit, 
        "streamlimit", streamlimit, "where", where)
    data <- RSmap.postQuery(query)
    if (length(data) == 0) {
        write(paste(".next: no data found after", ref, "where", 
            where), stderr())
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
