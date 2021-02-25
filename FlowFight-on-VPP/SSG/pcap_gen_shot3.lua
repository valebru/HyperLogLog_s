--- Forward packets between two ports
local lm     = require "libmoon"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local memory = require "memory"
local timer  = require "timer"
local math   = require "math"
local bit    = require "bitopt"
local ffi    = require "ffi"
local icmp   = require "proto.icmp"
local pcap   = require "pcap"
local vtask  = require ("valetask") 


function configure(parser)
	parser:argument("filename", "Filename with classbench trace"):args(1)
	parser:option("-s --size", "Packet size."):default(60):convert(tonumber)
	return parser:parse()
end

function master(args)

	local file=args.filename
	print("Filename: " .. file)
	local tab_thr = 900

	local rules_icmp = {{}}
	local icmp_index=1
	local rules_tcp = {{}}
	local tcp_index=1
	local rules_udp = {{}}
	local udp_index=1
	local k=-1

	--File parsing
	local f = io.open(file, "rb")

	--for k,v in pairs(lines) do
	--for line in io.lines(file) do
	for v in io.lines(file) do
		k=k+1
		--print('line[' .. k .. ']', v)
		local words = {}
		local i=1


		for w in (v .. "\t"):gmatch("([^\t]*)\t") do
			table.insert(words, tonumber(w))
			i=i+1
		end

		if tonumber(words[5]) == 1 then
			table.insert(rules_icmp[icmp_index], words)
			if table.getn(rules_icmp[icmp_index]) > tab_thr then
				icmp_index = icmp_index + 1;
				table.insert(rules_icmp, {})
				--print('icmp ' .. icmp_index)
			end
		elseif tonumber(words[5]) == 6 then
			table.insert(rules_tcp[tcp_index], words)
			if table.getn(rules_tcp[tcp_index]) > tab_thr then
				tcp_index = tcp_index + 1;
				table.insert(rules_tcp, {})
				--print('tcp ' .. tcp_index)
			end
		else 
			table.insert(rules_udp[udp_index], words)
			if table.getn(rules_udp[udp_index]) > tab_thr then
				udp_index = udp_index + 1;
				table.insert(rules_udp, {})
				--print('udp ' .. udp_index)
			end
		end
	end
	f:close() 

--[[
	for k,v in pairs(rules_icmp) do
		io.write("line " .. k .. ": ")
		for i,j in pairs(v) do
			io.write(" " .. j)
		end
		io.write("\n")
	end
--]]
	

	local tcp_nrules = 0
	local udp_nrules = 0
	local icmp_nrules = 0

	print("TCP: "..table.getn(rules_tcp))
	for k,v in pairs(rules_tcp) do
		tcp_nrules = tcp_nrules + table.getn(v)
		--print("Index "..k.." : "..table.getn(v))
	end
	print("UDP: "..table.getn(rules_udp))
	for k,v in pairs(rules_udp) do
		udp_nrules = udp_nrules + table.getn(v)
		--print("Index "..k.." : "..table.getn(v))
	end
	print("ICMP: "..table.getn(rules_icmp))
	for k,v in pairs(rules_icmp) do
		icmp_nrules = icmp_nrules + table.getn(v)
		--print("Index "..k.." : "..table.getn(v))
	end

	print("Tcp: " .. tcp_nrules .. " |Udp: " .. udp_nrules .. " |Icmp: " .. icmp_nrules)
	local tot_rules = tcp_nrules + udp_nrules + icmp_nrules 
	print("Tot_rules: " .. tot_rules)
	print("Traceset parser ends")


	print("Pkt size: " .. args.size)	
	pkt_size = args.size


	task_forward_tcp(rules_tcp, pkt_size)
	task_forward_udp(rules_udp, pkt_size)
	task_forward_icmp(rules_icmp, pkt_size)


	lm.waitForTasks()

end

--  Task looping on huge tables

function task_forward_tcp(rules, framesize)
	local tcpPayloadLen = framesize - 14 - 20 - 20
	local tcpPayload = ffi.new("uint8_t[?]", tcpPayloadLen)
	for i = 0, tcpPayloadLen - 1 do
		--tcpPayload[i] = bit:band(i, 0xF)
		tcpPayload[i] = bit:band(math.random(0xFF), 0xFF)
	end

	local mem = memory.createMemPool(function(buf)
		local pkt = buf:getTcpPacket()
		pkt:fill{
			pktlength=framesize,
			ethSrc = txQueue,
			ethDst = "00:25:b5:01:00:0f",
			tcpPsh = 1, 
			tcpAck = 1, 
			tcpSeqNumber = bit:band(math.random(0xFF), 0xFF),
			tcpWindow = 15
		}

		-- fill udp payload with prepared tcp payload
		ffi.copy(pkt.payload, tcpPayload, tcpPayloadLen)
	end)

	local writer
	writer = pcap:newWriter("tmp-tcp.pcap")

	for i,j in pairs(rules) do
		if table.getn(j) > 0 then
			simple_forward_tcp(j, framesize, mem, writer)
		end
	end
	writer:close()
	memory.freeMemPools()
	lm.stop()
end

function task_forward_udp(rules, framesize)
	local udpPayloadLen = framesize - 14 - 20 - 8
	local udpPayload = ffi.new("uint8_t[?]", udpPayloadLen)
	for i = 0, udpPayloadLen - 1 do
		--udpPayload[i] = bit:band(i, 0xF)
		udpPayload[i] = bit:band(math.random(0xFF), 0xFF)
	end

	local mem = memory.createMemPool(function(buf)
		local pkt = buf:getUdpPacket()
		pkt:fill{
			pktlength=framesize,
			ethSrc = txQueue,
			ethDst = "00:25:b5:01:00:0f",
		}
		-- fill udp payload with prepared udp payload
		ffi.copy(pkt.payload, udpPayload, udpPayloadLen)

	end)


	local writer
	writer = pcap:newWriter("tmp-udp.pcap")

	for i,j in pairs(rules) do
		if table.getn(j) > 0 then
			simple_forward_udp(j, framesize, mem, writer)
		end
	end
	writer:close()
	memory.freeMemPools()
	lm.stop()
end

function task_forward_icmp(rules, framesize)
	local icmpBodyLen = framesize - 14 - 20 - 4
	local icmpBody = ffi.new("uint8_t[?]", icmpBodyLen)
	for i = 0, icmpBodyLen - 1 do
		--icmpBody[i] = bit:band(i, 0xF)
		icmpBody[i] = bit:band(math.random(0xFF), 0xFF)
	end

	local mem = memory.createMemPool(function(buf)
		local pkt = buf:getIcmpPacket()
		pkt:fill{
			pktlength=framesize,
			ethSrc = txQueue,
			ethDst = "00:25:b5:01:00:0f",
			pkt.icmp:setType(icmp.ECHO_REPLY.type)
		}

		-- fill udp payload with prepared tcp payload
		ffi.copy(pkt.payload, icmpBody, icmpBodyLen)
	end)

	local writer
	writer = pcap:newWriter("tmp-icmp.pcap")

	for i,j in pairs(rules) do
		if table.getn(j) > 0 then
			simple_forward_icmp(j, framesize, mem, writer)
		end
	end
	writer:close()
	memory.freeMemPools()
	lm.stop()
end

--  TASK details (sending packets)
function simple_forward_tcp(rules, framesize, mem, writer)
        local counter=1
	local nrules=table.getn(rules)


	local bufs = mem:bufArray()

	local totalSent = 0
	while (true) do
		bufs:alloc(framesize)

		for _, buf in ipairs(bufs) do
			local batchTime = lm.getTime()
			local pkt = buf:getTcpPacket()
			local pointer = rules[counter]
			pkt.ip4:setSrc(pointer[1])
			pkt.ip4:setDst(pointer[2])
			pkt.tcp:setSrcPort(pointer[3])
			pkt.tcp:setDstPort(pointer[4])
			--print(pointer[1] .. ", " .. pointer[2] .. ", " .. pointer[3] .. ", " .. pointer[4] )
			--buf:dump()
			--pkt.ip4:getString()
			bufs:offloadTcpChecksums()
			writer:writeBuf(batchTime, buf, 64)
			buf:free()
			if counter < (nrules) then counter = counter +1 
			else break end
		end
		if counter == (nrules) then break end
	end

	bufs:freeAll()
--	printf ("Total sent: %d", totalSent)


end


function simple_forward_udp(rules, framesize, mem, writer)
        local counter=1
	local nrules=table.getn(rules)

	local bufs = mem:bufArray()

	local totalSent = 0
	while (true) do
		bufs:alloc(framesize)

		for _, buf in ipairs(bufs) do
			local batchTime = lm.getTime()
			local pkt = buf:getUdpPacket()
			local pointer = rules[counter]
			pkt.ip4:setSrc(pointer[1])
			pkt.ip4:setDst(pointer[2])
			pkt.udp:setSrcPort(pointer[3])
			pkt.udp:setDstPort(pointer[4])
			--print(pointer[1] .. ", " .. pointer[2] .. ", " .. pointer[3] .. ", " .. pointer[4] )
			--buf:dump()
			--pkt.ip4:getString()
			bufs:offloadUdpChecksums() 
			writer:writeBuf(batchTime, buf, 64)
			buf:free()
			if counter < (nrules) then counter = counter +1 
			else break end
		end
		if counter == (nrules) then break end
	end

	bufs:freeAll()
--	printf ("Total sent: %d", totalSent)


end


function simple_forward_icmp(rules, framesize, mem, writer)
        local counter=1
	local nrules=table.getn(rules)

	local bufs = mem:bufArray()

	local totalSent = 0
	while (true) do
		bufs:alloc(framesize)

		for _, buf in ipairs(bufs) do
			local batchTime = lm.getTime()
			local pkt = buf:getIcmpPacket()
			local pointer = rules[counter]
			pkt.ip4:setSrc(pointer[1])
			pkt.ip4:setDst(pointer[2])
			pkt.icmp:calculateChecksum(pkt.ip4:getLength() - pkt.ip4:getHeaderLength() * 4)
			pkt.ip4:setChecksum(0)
			--print(pointer[1] .. ", " .. pointer[2] .. ", " .. pointer[3] .. ", " .. pointer[4] )
			--buf:dump()
			--pkt.ip4:getString()
			bufs:offloadIPChecksums()
			writer:writeBuf(batchTime, buf, 64)
			buf:free()
			if counter < (nrules) then counter = counter +1 
			else break end
		end
		if counter == (nrules) then break end
	end

	bufs:freeAll()
--	printf ("Total sent: %d", totalSent)


end


