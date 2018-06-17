[![Build Status](https://travis-ci.org/FLCN17/JuliaCipher.jl.svg?branch=master)](https://travis-ci.org/FLCN17/JuliaCipher.jl)
[![Coverage Status](https://coveralls.io/repos/FLCN17/JuliaCipher.jl/badge.svg?branch=master&service=github)](https://coveralls.io/github/FLCN17/JuliaCipher.jl?branch=master)
[![codecov.io](http://codecov.io/github/FLCN17/JuliaCipher.jl/coverage.svg?branch=master)](http://codecov.io/github/FLCN17/JuliaCipher.jl?branch=master)
# JuliaCipher
This program is basically a quick method to lock up files over a publicly accessable medium,
-and have the retreivable based on a shared file and phrase

The code consits of a heavily modified ADFGVX cipher, which is itself a fancy adaptation of the polybius square. 
-The chart is a file the contains a dict of code pairings to letters. It is used to en/de-code the messages. 
-The codespace dictates both the size and the characters used to encode the message.
--Any set of 10 characters may be used, provided the characters are unique
--Typically ADFGVX was used for alphanumerical encoding, but to accomidate the characters used in programming,
--and to avoid a solution similar to old telegrams (ie STOP for punctuation), 10 characters are used.
---NOTE: While the program is written in Julia, and can take advantage of the entire unicode range using a 10+ codespace,
---it is a niche feature which serves only to bloat the size of the chart file and the number of operation involved making the decode chart.
-The phrase is involved in the second stage of encipherment, which involves:
--sorting the entire array of characters aligned beneath the phrase, alphabetically
--returning the sorted code as the final output
-The combination of code chart and secret phrase provide the security of two disparate key systems, while maintaining simplicity and ease
--Care must be taken to maintain the privacy of both the chart and the phrase; compromise of one provides insight into the other, 
--and loss of both requires a new chart and immidiate retreival, de-coding, and re-encoding of any compromised encoded documents.
--Teirs of charts may be used, as well as varient encoding schema to provide additional layers of security, but an attacker able to 
--compromise the first level will probably be able to break subsequent. This is a padlock to deter the casual attacker.
Above all, never trust a new, undocumented, and home-brewed cipher method for anything actually sensitive. 

#(!)Use literally any other popular method is you want true security(!)#

