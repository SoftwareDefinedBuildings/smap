\name{RSmap.data}
\alias{RSmap.data}
%- Also NEED an '\alias' for EACH other topic documented here.
\title{
RSmap.data
}
\description{
%%  ~~ A concise (1-5 lines) description of what the function does. ~~
}
\usage{
RSmap.data(where, start, end, limit = 10000, streamlimit = 10)
}
%- maybe also 'usage' for other objects documented here.
\arguments{
  \item{where}{
%%     ~~Describe \code{where} here~~
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
  \item{streamlimit}{
%%     ~~Describe \code{streamlimit} here~~
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
