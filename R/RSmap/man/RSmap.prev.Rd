\name{RSmap.prev}
\alias{RSmap.prev}
%- Also NEED an '\alias' for EACH other topic documented here.
\title{
RSmap.prev
}
\description{
%%  ~~ A concise (1-5 lines) description of what the function does. ~~
}
\usage{
RSmap.prev(where, ref, limit = 1, streamlimit = 10)
}
%- maybe also 'usage' for other objects documented here.
\arguments{
  \item{where}{
%%     ~~Describe \code{where} here~~
}
  \item{ref}{
%%     ~~Describe \code{ref} here~~
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
function (where, ref, limit = 1, streamlimit = 10) 
{
    query <- paste("select data before", ref, "limit", limit, 
        "streamlimit", streamlimit, "where", where)
    data <- RSmap.postQuery(query)
    if (length(data) == 0) {
        write(paste(".prev: no data found before", ref, "where", 
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
