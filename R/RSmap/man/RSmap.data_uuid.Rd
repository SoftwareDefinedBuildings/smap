\name{RSmap.data_uuid}
\alias{RSmap.data_uuid}
%- Also NEED an '\alias' for EACH other topic documented here.
\title{
RSmap.data_uuid
}
\description{
%%  ~~ A concise (1-5 lines) description of what the function does. ~~
}
\usage{
RSmap.data_uuid(uuids, start, end, limit)
}
%- maybe also 'usage' for other objects documented here.
\arguments{
  \item{uuids}{
%%     ~~Describe \code{uuids} here~~
}
  \item{start}{
%%     ~~Describe \code{start} here~~
}
  \item{end}{
%%     ~~Describe \code{end} here~~
}
  \item{limit}{
%%     ~~Describe \code{limit} here~~
}
}
\details{
%%  ~~ If necessary, more details than the description above ~~
}
\value{
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
%%  ~~who you are~~
}
\note{
%%  ~~further notes~~
}

%% ~Make other sections like Warning with \section{Warning }{....} ~

\seealso{
%% ~~objects to See Also as \code{\link{help}}, ~~~
}
\examples{
##---- Should be DIRECTLY executable !! ----
##-- ==>  Define data, use random,
##--	or do  help(data=index)  for the standard data sets.

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
