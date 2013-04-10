\name{RSmap}
\alias{RSmap}
%- Also NEED an '\alias' for EACH other topic documented here.
\title{
RSmap
}
\description{
%%  ~~ A concise (1-5 lines) description of what the function does. ~~
}
\usage{
RSmap(url, key = NULL, private = FALSE, timeout = 50)
}
%- maybe also 'usage' for other objects documented here.
\arguments{
  \item{url}{
%%     ~~Describe \code{url} here~~
}
  \item{key}{
%%     ~~Describe \code{key} here~~
}
  \item{private}{
%%     ~~Describe \code{private} here~~
}
  \item{timeout}{
%%     ~~Describe \code{timeout} here~~
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
function (url, key = NULL, private = FALSE, timeout = 50) 
{
    keyStr <- paste(sapply(key, function(k) {
        paste("key=", k, sep = "")
    }), collapse = "&")
    privateStr <- if (private) 
        "&private="
    else ""
    urlEnc <- paste(url, "/api/query?", keyStr, privateStr, sep = "")
    .RSmap$data <- list(urlEnc = urlEnc, keyStr = keyStr, privateStr = privateStr, 
        timeout = timeout)
  }
}
% Add one or more standard keywords, see file 'KEYWORDS' in the
% R documentation directory.
\keyword{ ~kwd1 }
\keyword{ ~kwd2 }% __ONLY ONE__ keyword per line
