\name{RSmap.tags}
\alias{RSmap.tags}
%- Also NEED an '\alias' for EACH other topic documented here.
\title{
RSmap.tags
}
\description{
    Load the tags for all streams matching the where clause.
%%  ~~ A concise (1-5 lines) description of what the function does. ~~
}
\usage{
RSmap.tags(where)
}
%- maybe also 'usage' for other objects documented here.
\arguments{
  \item{where}{
The ArchiverQuery selector for finding time series
}
}
\details{
%%  ~~ If necessary, more details than the description above ~~
}
\value{
    Returns an R nested list structure containing the metadata of the streams 
    matching the where clause.
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
tags <- RSmap.tags("Metadata/Extra/Type = 'oat'")

## The function is currently defined as
function (where) 
{
    query <- paste("select * where ", where)
    res <- RSmap.postQuery(query)
    if (length(res) == 0) {
        write(paste(".tags: no tags found for streams where", 
            where), stderr())
    }
    res
  }
}
% Add one or more standard keywords, see file 'KEYWORDS' in the
% R documentation directory.
\keyword{ ~kwd1 }
\keyword{ ~kwd2 }% __ONLY ONE__ keyword per line
