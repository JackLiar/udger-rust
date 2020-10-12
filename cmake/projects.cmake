include(ExternalProject)

include(ragel)
include(boost)
include(pcre)
include(hyperscan)

ExternalProject_Add_StepDependencies(hyperscan configure ragel boost libpcre)
