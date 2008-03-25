----------------------------------------------------------------------------
-- $Id: rsa.lua,v 1.1 2008-03-25 18:02:02 jasonsantos Exp $
----------------------------------------------------------------------------
local core = require"rsa.core"
local print = print
local string = require"string"
local table = require"table"

table.foreach(core, print)


module ("rsa")

p, P = core.genkey()

--table.foreach(p, print)
print"\n\n------------------------------\n\n"
--table.foreach(P, print)

pubkey = {
N = "9292758453063D803DD603D5E777D788" ..
    "8ED1D5BF35786190FA2F23EBC0848AEA" ..
    "DDA92CA6C3D80B32C4D109BE0F36D6AE" ..
    "7130B9CED7ACDF54CFC7555AC14EEBAB" ..
    "93A89813FBF3C4F8066D2D800F7C38A8" ..
    "1AE31942917403FF4946B0A83D3D3E05" ..
    "EE57C6F5F5606FB5D4BC6CD34EE0801A" ..
    "5E94BB77B07507233A0BC7BAC8F90F79",

E = "10001",

}

prvkey = {
N = "9292758453063D803DD603D5E777D788" ..
    "8ED1D5BF35786190FA2F23EBC0848AEA" ..
    "DDA92CA6C3D80B32C4D109BE0F36D6AE" ..
    "7130B9CED7ACDF54CFC7555AC14EEBAB" ..
    "93A89813FBF3C4F8066D2D800F7C38A8" ..
    "1AE31942917403FF4946B0A83D3D3E05" ..
    "EE57C6F5F5606FB5D4BC6CD34EE0801A" ..
    "5E94BB77B07507233A0BC7BAC8F90F79",

E = "10001",

D = "24BF6185468786FDD303083D25E64EFC" ..
    "66CA472BC44D253102F8B4A9D3BFA750" ..
    "91386C0077937FE33FA3252D28855837" ..
    "AE1B484A8A9A45F7EE8C0C634F99E8CD" ..
    "DF79C5CE07EE72C7F123142198164234" ..
    "CABB724CF78B8173B9F880FC86322407" ..
    "AF1FEDFDDE2BEB674CA15F3E81A1521E" ..
    "071513A1E85B5DFA031F21ECAE91A34D",
    
P = "C36D0EB7FCD285223CFB5AABA5BDA3D8" ..
    "2C01CAD19EA484A87EA4377637E75500" ..
    "FCB2005C5C7DD6EC4AC023CDA285D796" ..
    "C3D9E75E1EFC42488BB4F1D13AC30A57",
                
Q  = "C000DF51A7C77AE8D7C7370C1FF55B69" ..
    "E211C2B9E5DB1ED0BF61D0D9899620F4" ..
    "910E4168387E3C30AA1E00C339A79508" ..
    "8452DD96A9A5EA5D9DCA68DA636032AF",
    
DP = "C1ACF567564274FB07A0BBAD5D26E298" ..
    "3C94D22288ACD763FD8E5600ED4A702D" ..
    "F84198A5F06C2E72236AE490C93F07F8" ..
    "3CC559CD27BC2D1CA488811730BB5725",
    
DQ = "4959CBF6F8FEF750AEE6977C155579C7" ..
    "D8AAEA56749EA28623272E4F7D0592AF" ..
    "7C1F1313CAC9471B5C523BFE592F517B" ..
    "407A1BD76C164B93DA2D32A383E58357",
                
QP = "9AE7FBC99546432DF71896FC239EADAE" ..
    "F38D18D2B2F0E2DD275AA977E2BF4411" ..
    "F5A3B2A5D33605AEBBCCBA7FEB9F2D2F" ..
    "A74206CEC169D74BF5A8C50D6F48EA08"
}

plaintext =     "There is no bar to make against your highness claim to France"

hexCiphertext =    "157dd4941a53c828a7611629eddfbb457f2eae899f445ffc1746c3f907"..
                "64cfe47bc5794e65ff683bd7922af995cd654c94c1efdbf7f14ba236a5ca99ab2761b30b995a30d7"..
                "bb9e4b818a480051a8e85a75d18b3127d8432d2db7dd2b3f2189d34c0fecac85f4a1293bf88e9922"..
                "6a461f96bf2a3e4b089e386f39c74050020e6a"

local ciphertext = core.crypt(plaintext, pubkey)
print('ciphertext [[')
print((string.gsub(ciphertext, ".", function (c)
           return string.format("%02x", string.byte(c))
         end)))
print(']]')


local returntext = core.decrypt(ciphertext, prvkey, "private")
print('returntext [[')
print((string.gsub(returntext, ".", function (c)
           return string.format("%02x", string.byte(c))
         end)))
print(']] => "' .. returntext .. '"\n')



--[=====[
print[[------------------------------------------]]
table.foreach(prvkey, print)
print[[------------------------------------------]]
table.foreach(ciphertext, print)
print[[------------------------------------------]]


--[=[
print('message [[')
print(core.decrypt(ciphertext, P))
print(']]')
]=]
]=====]
