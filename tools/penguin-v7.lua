-- Wireshark dissector for the Penguin v7 protocol
penguinv7_proto = Proto("penguin-v7", "Penguin v7 Protocol")

local opcodes = {
    [0] = "Connect",
    [1] = "Acknowledge",
    [2] = "Reset",
    [3] = "Finish",
    [4] = "Push",
    [5] = "Bind",
    [6] = "Datagram"
}

local bind_types = {
    [1] = "TCP",
    [3] = "UDP"
}

local f_opcode = ProtoField.uint8("penguin-v7.opcode", "Operation Code", base.DEC, opcodes)
local f_flow_id = ProtoField.uint32("penguin-v7.flow_id", "Flow ID", base.HEX)
local f_rwnd = ProtoField.uint64("penguin-v7.rwnd", "Buffer Size")
local f_ack = ProtoField.uint64("penguin-v7.ack", "Acknowledge Amount")
local f_target_port = ProtoField.uint16("penguin-v7.target_port", "Target Port")
local f_target_host = ProtoField.string("penguin-v7.target_host", "Target Host")
local f_host_len = ProtoField.uint8("penguin-v7.host_len", "Host Length")
local f_bind_type = ProtoField.uint8("penguin-v7.bind_type", "Bind Type", base.DEC, bind_types)
local f_payload = ProtoField.bytes("penguin-v7.payload", "Payload")

penguinv7_proto.fields = {
    f_opcode,
    f_flow_id,
    f_rwnd,
    f_ack,
    f_target_port,
    f_target_host,
    f_host_len,
    f_bind_type,
    f_payload
}

function penguinv7_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "Penguin v7"
    local subtree = tree:add(penguinv7_proto, buffer(), "Penguin v7 Protocol")
    local first_byte = buffer(0, 1):uint()
    if (first_byte >> 4) ~= 7 then
        -- Not penguin-v7
        return 0
    end
    local opcode = first_byte & 0x0F;
    subtree:add(f_opcode, opcode)
    subtree:add(f_flow_id, buffer(1, 4))
    if opcode == 0 then
        -- Connect
        subtree:add(f_rwnd, buffer(5, 4))
        subtree:add(f_target_port, buffer(9, 2))
        subtree:add(f_target_host, buffer(11))
    elseif opcode == 1 then
        -- Acknowledge
        subtree:add(f_ack, buffer(5, 4))
    elseif opcode == 2 then
        -- Reset
    elseif opcode == 3 then
        -- Finish
    elseif opcode == 4 then
        -- Push
        subtree:add(f_payload, buffer(5))
    elseif opcode == 5 then
        -- Bind
        local bind_type = buffer(5, 1):uint()
        if bind_types[bind_type] == nil then
            return 0
        end
        subtree:add(f_bind_type, bind_type)
        subtree:add(f_target_port, buffer(6, 2))
        subtree:add(f_target_host, buffer(8))
    elseif opcode == 6 then
        -- Datagram
        local host_len = buffer(5, 1):uint()
        subtree:add(f_host_len, host_len)
        subtree:add(f_target_port, buffer(6, 2))
        subtree:add(f_target_host, buffer(8, host_len))
        -- Remaining is data
        subtree:add(f_payload, buffer(8 + host_len))
    else
        -- Not penguin-v7
        return 0
    end
end
local ws_dissector_table = DissectorTable.get("ws.protocol")
ws_dissector_table:add("penguin-v7", penguinv7_proto)
