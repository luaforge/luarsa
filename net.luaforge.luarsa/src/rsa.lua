----------------------------------------------------------------------------
-- $Id: rsa.lua,v 1.1 2008-03-25 18:02:02 jasonsantos Exp $
----------------------------------------------------------------------------
local core = require"rsa.core"
local print = print
local string = require"string"
local table = require"table"
--[===[
table.foreach(core, print)


module ("rsa")

p, P = core.genkey()

table.foreach(p, print)
print"\n\n------------------------------\n\n"
table.foreach(P, print)

local ciphertext = core.crypt("Macarronada", p)
print('ciphertext [[')
print(ciphertext)
print(']]')


print('message [[')
print(core.decrypt(ciphertext, P))
print(']]')

]===]

print(string.format("%x", -1024))