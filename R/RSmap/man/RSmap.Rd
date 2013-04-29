\name{RSmap}
\alias{RSmap}
%- Also NEED an '\alias' for EACH other topic documented here.
\title{
RSmap
}
\description{
    Create a connection to a sMAP archive located at \code{url}. The url should
    point to the root resource of the archive. API keys can be provided as
    a list, as \code{c(<key1>, <key2>)}. Set \code{private} to \code{TRUE} if you
    only want to get private streams. This determines the url and other
    parameters used in the other RSmap functions when you retrieve data, and is
    required to use the other RSmap functions.
}
\usage{
RSmap(url, key = NULL, private = FALSE, timeout = 50)
}
%- maybe also 'usage' for other objects documented here.
\arguments{
  \item{url}{
A sMAP archiver URL.
}
  \item{key}{
An API key or list of API keys.
}
  \item{private}{
Set to TRUE to only retrieve private data according to the subscriptions indicated by the API key(s). 
}
  \item{timeout}{
Amount of time to wait for a server response, in seconds.
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

# Create a connection to the openbms archiver
RSmap("http://new.openbms.org/backend")

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
