
""" JuliaCipher-
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
"""

module JuliaCipher

using HDF5, JLD


""" saveChart(chart::Dict, chartLoc::String)

Handles saving the chart to file, given the location. """

function saveChart(chart::Dict, chartLoc::String)
	#saves a chart to file in a nice easy format. -NEEDS PERMISSIONS
	#handle bad permissions? where should it go?
	save(chartLoc, "chart", chart)
	
end


""" loadChart(chartLoc::String)

Handles loading a chart from given location, returns as a Dict. """

function loadChart(chartLoc::String)
	#grabs a chart from a file, and loads it properly
	#do a check if you even can first, then pop back a new chart? flag to allow new charting? just outright reject?
	return load(chartLoc)["chart"]
end


""" createChart(chartLoc::String; codeSpace::String="ADFGLTVXYZ", alphabetPool::String="abcde...")

Handles creation of chart based on a given codespace and alphabet. Assumes standard if none given. """

function createChart(chartLoc::String; codeSpace::String="ADFGLTVXYZ", alphabetPool::String="abcdefghiklmnopqrstuvwxyzj0123456789{}()[],.:;+-=*/@%_~!?#^&'<>|ABCDEFGHIJKLMNOPQRSTUVWXYZ `\u0000\u000D\u0020\u005C\u0024\u0022\u0009\u000A")
	chart=Dict()
	charArray=split(alphabetPool, "")
	for i in 1:length(codeSpace)
		for j in 0:length(codeSpace)-1
			randSpot=rand(Int8)%length(charArray)
			randSpot=(randSpot==0?1:(randSpot<0?randSpot*-1:randSpot))
			chart[charArray[randSpot][1]] = string(codeSpace[i])*string(codeSpace[j+1])
			deleteat!(charArray, randSpot)
		end
	end
	saveChart(chart, chartLoc)
	return chart
end


""" encryptFile(fileName::String, passPhrase::String, chart::String)

Handles encryption of file-loads a file from given location, uses given phrase, loads a chart from given location. """

function encryptFile(fileName::String, passPhrase::String, chart::String)
	chart = loadChart(chart) #catch an error if no chart(?)
	#encrypt phase
	preString=""
	inFile = open(fileName,"r")
	fname=split(fileName, '.')\
	fnameOut=fname[1]*".adfgvx"*"."*fname[end]
	outFile = open(fnameOut, "w")
	inString = readstring(inFile)
	for char in inString
		preString*=get(chart, char, 'x')
	end
	fillAmt=length(preString)%length(passPhrase)
	if fillAmt > 0
		for i in 1:(length(passPhrase)-fillAmt)
			preString*=chart['#']
		end
	end

	#phraseShifting phase- take phrase, arrange letters below, sort by phrase alphabetically
	#-turn code letters into array with len(phrase) cols and however many rows
	#-sort array, carry the letters array along with it.
	#=
	codeArray=fill(' ', Int(ceil(length(preString)/length(passPhrase))), length(passPhrase))
	#codeArray=[ceil(length(outString)/length(prePhrase))][length(prePhrase)]
	k=1
	for i in 1:Int(ceil(length(preString)/length(passPhrase)))
		for j in 1:length(passPhrase)
			codeArray[i, j]=preString[k]
			k+=1
		end
	end
	#sortedString=phraseSort(codeArray, passPhrase, true)
	=#
	#temp fix/bypass
	sortedString=preString

	#output phase
	outString=""
	spacing=0; lines=0
	for char in sortedString
		if spacing == 8
			outString*=" "
			spacing=0
			lines+=1
		end
		if lines == 8
			outString*="\n"
			lines=0
		end
		outString*=char
		spacing+=1
	end
	print(outFile, outString)
	close(outFile); close(inFile)
end


""" decryptFile(fileName::String, passPhrase::String, chartLoc::String)

Handles decryption of file- given location of file (.adfgvx.ext), given phrase, and given the chart location. """

function decryptFile(fileName::String, passPhrase::String, chartLoc::String)
	chart=loadChart(chartLoc)
	#reverse the Dict
	decodeChart=Dict()
	for(key, value) in chart
		decodeChart[value]=key
	end
	#reading from file
	fname=split(fileName, '.')
	fnameOut = fname[1]*".test"*"."*fname[end]
	outFile = open(fnameOut, "w")
	spacing=0; lines=0
	inFile = open(fileName,"r")
	fileString = readstring(inFile)

	#phraseshifting-
	#take filestring, unshift it according to phrase, carry on decoding
	fileArray = split(fileString)
	codeArray=fill(' ', length(passPhrase), Int(ceil(length(fileString)/length(passPhrase))))
	#codeArray=[ceil(length(outString)/length(prePhrase))][length(prePhrase)]
	#=
	k=1
	for i in 1:Int(ceil(length(fileString)/length(passPhrase)))
		for j in 1:length(passPhrase)
			codeArray[j, i]=fileArray[k]
			k+=1
		end
	end
	sortedArray=phraseSort(codeArray, passPhrase, false)
	=#

	#output phase
	#can do this better- allow for custom block sizes, and just grab 2 chars at a time, throw them at the chart, keep on going
	for block in fileArray
		for char in 1:2:length(block)
			code = string(block[char])*string(block[char+1])
			print(outFile, get(decodeChart, code, 'x'))
		end
	end
	close(outFile); close(inFile)
end


""" phraseSort(message::Any, passPhrase::String, encoding::Bool)

Handles sorting the entire 'message' by a given phrase. also takes a flag to decide if shifting for encoding or decoding. """

function phraseSort(message::Any, passPhrase::String, encoding::Bool)
	postPhrase=[]
	prePhrase=split(passPhrase,"")
	stringOut=message #just because i dont want to do this YET
	if encoding == true
		#encoding
		#sort the phrase into alphabetical order, and drag the array 'rows' with you
		#for loops? per char in that char of phrase? seems slow-
		#get offset library - phrase => aehprs == [3,1,2,-3,1,-4], and just apply the offsets when re-assigning chars to new/duped array
		#grab chars in phrase, and math out their ascii offsets? then simply put all chars in newArray[j+offset[j], i]

		#return as finished string
	else
		#decoding
		#like above, but do opposite- subtract offsets when putting in out array- keep single by putting in newArray[i+(j-1)*len(phrase)]

		#return as a single dimensional code char array
	end

	return stringOut #prolly not stringout
end


""" testModule()

Runs a very basic test of the programs features- creates chart, encrypts, decrypts. """

function testModule()
	fname = "/home/cory/Documents/JuliaCipher/JuliaCipher/New Folder/ImportRecord.jl"
	dname = "/home/cory/Documents/JuliaCipher/JuliaCipher/New Folder/ImportRecord.adfgvx.jl"
	#chart = createChart("chart.jld")
	#print(chart)
	encryptFile(fname, "phrase", "chart.jld")
	decryptFile(dname, "phrase", "chart.jld")
end

end