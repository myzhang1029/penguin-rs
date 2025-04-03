-- Wireshark dissector for the Penguin v7 protocol
penguinv6_proto = Proto("penguin-v7", "Penguin v7 Protocol")

local f_type = ProtoField.string("penguin-v7.type", "Type")
local f_forwarding_port = ProtoField.uint16("penguin-v7.forwarding_port", "Forwarding Port")
local f_forwarding_host = ProtoField.string("penguin-v7.forwarding_host", "Forwarding Host")
local f_payload = ProtoField.bytes("penguin-v7.payload", "Payload")
local f_sport = ProtoField.uint16("penguin-v7.sport", "Source Port")
local f_dport = ProtoField.uint16("penguin-v7.dport", "Destination Port")
-- stream only
local f_rwnd = ProtoField.uint64("penguin-v7.rwnd", "Buffer Size")
local f_opcode = ProtoField.string("penguin-v7.opcode", "Operation Code")
local f_ack = ProtoField.uint64("penguin-v7.ack", "Acknowledge Amount")
-- datagram only
local f_host_len = ProtoField.uint8("penguin-v7.host_len", "Host Length")

penguinv7_proto.fields = {
    f_type,
    f_forwarding_port,
    f_forwarding_host,
    f_payload,
    f_sport,
    f_dport,
    f_rwnd,
    f_opcode,
    f_ack,
    f_host_len
}

function penguinv7_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "Penguin v7"
    local subtree = tree:add(penguinv7_proto, buffer(), "Penguin v7 Protocol")
    local frame_type = buffer(0, 1):uint()
    if frame_type == 1 then
        -- Stream Frame
        subtree:add(f_type, "stream")
        local opcode = buffer(1, 1):uint()
        subtree:add(f_sport, buffer(2, 2))
        subtree:add(f_dport, buffer(4, 2))
        local opcodes = {
            [0] = "Syn",
            [2] = "Ack",
            [3] = "Rst",
            [4] = "Fin",
            [5] = "Psh",
            [6] = "Bnd"
        }
        if opcodes[opcode] ~= nil then
            subtree:add(f_opcode, opcodes[opcode])
        else
            -- Not penguin-v6
            return 0
        end
        if opcode == 0 then
            -- Syn rwnd
            subtree:add(f_rwnd, buffer(6, 8))
            -- Syn forwarding target
            subtree:add(f_forwarding_port, buffer(14, 2))
            subtree:add(f_forwarding_host, buffer(16))
        elseif flag == 2 then
            -- Ack amount
            subtree:add(f_ack, buffer(6, 8))
        elseif flag == 5 then
            -- Remaining is data
            subtree:add(f_payload, buffer(6))
        end
    elseif frame_type == 3 then
        -- Datagram Frame
        subtree:add(f_type, "datagram")
        local hostlen = buffer(1, 1):uint()
        subtree:add(f_host_len, hostlen)
        subtree:add(f_sport, buffer(2, 2))
        subtree:add(f_dport, buffer(4, 2))
        subtree:add(f_forwarding_port, buffer(6, 2))
        subtree:add(f_forwarding_host, buffer(8, hostlen))
        -- Remaining is data
        subtree:add(f_payload, buffer(8 + hostlen))
    else
        -- Not penguin-v6
        return 0
    end
end
local ws_dissector_table = DissectorTable.get("ws.protocol")
ws_dissector_table:add("penguin-v7", penguinv7_proto)
