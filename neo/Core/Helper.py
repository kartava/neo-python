from neo.Blockchain import GetBlockchain,GetStateReader
from neo.Cryptography.Crypto import *
from neo.IO.BinaryWriter import BinaryWriter
from neo.IO.MemoryStream import MemoryStream,StreamManager
from neo.UInt160 import UInt160
from neo.VM.ScriptBuilder import ScriptBuilder
from neo.SmartContract.ApplicationEngine import ApplicationEngine
from neo.Fixed8 import Fixed8
from neo.SmartContract import TriggerType

class Helper(object):


    @staticmethod
    def WeightedFilter(list):
        raise NotImplementedError()

    @staticmethod
    def WeightedAverage(list):
        raise NotImplementedError()

    @staticmethod
    def GetHashData(hashable):
        ms = StreamManager.GetStream()
        writer = BinaryWriter(ms)
        hashable.SerializeUnsigned(writer)
        ms.flush()
        retVal = ms.ToArray()
        StreamManager.ReleaseStream(ms)
        return retVal



    @staticmethod
    def Sign(verifiable, keypair):

#        stream = StreamManager.GetStream()

        pubkey = binascii.unhexlify( keypair.PublicKey.encode_point(True))
        print("pubkey %s\n%s " % (pubkey, binascii.hexlify(pubkey)))
        print("pubkeyfull %s " % keypair.PublicKey.encode_point(False))
        prikey = bytes(keypair.PrivateKey)
        print("private key %s " % prikey)
        hashdata = verifiable.GetHashData()

        res = Crypto.Default().Sign(hashdata, prikey, keypair.PublicKey)
        print("result %s " % res)
        return res

    @staticmethod
    def ToArray( value ):

        ms = StreamManager.GetStream()
        writer = BinaryWriter(ms)

        value.Serialize(writer)

        retVal = ms.ToArray()
        StreamManager.ReleaseStream(ms)
        
        return retVal

    @staticmethod
    def ToScriptHash(scripts):
        return Crypto.Hash160(scripts)


    @staticmethod
    def RawBytesToScriptHash(raw):
        rawh = binascii.unhexlify(raw)

        rawhashstr = binascii.unhexlify(bytes(Crypto.Hash160(rawh), encoding='utf-8'))
#        h160bytes = bytearray(rawhashstr)
#        h160bytes.reverse()
#        out = bytes(h160bytes.hex(), encoding='utf-8')
#        return out
        return UInt160(data=rawhashstr)

    @staticmethod
    def VerifyScripts(verifiable):



        try:
            hashes = verifiable.GetScriptHashesForVerifying()
        except Exception as e:
            print("couldng get script hashes %s " % e)
            return False

        if len(hashes) != len(verifiable.Scripts):
            print("hashes not same length as verifiable scripts")
            return False
        print("hello!!!! %s " % hashes)

        for i in range(0, len(hashes)):
            verification = verifiable.Scripts[i].VerificationScript


            print("verifying script: %s %s " % (hashes[i], verification))

            if len(verification) == 0:
                sb = ScriptBuilder()
                sb.EmitAppCall(hashes[i].Data)
                verification = sb.ToArray()

            else:
                if hashes[i] != verification:
                    print("hashes not equal to script hash!")
                    return False

            engine = ApplicationEngine(TriggerType.Verification, verifiable, GetBlockchain(), GetStateReader(), Fixed8.Zero())
            engine.LoadScript(verification, False)
            engine.LoadScript(verifiable.Scripts[i].InvocationScript, True)

            res =  engine.Execute()
            if not res:
                print("engine did not execune")
                return False
            else:

                print("engine did execute!")


            if engine.EvaluationStack.Count != 1 or not engine.EvaluationStack.Pop().GetBoolean():
                print("stack not one, or stack false")
                return False

        return True

    @staticmethod
    def IToBA(value):
        return [1 if digit == '1' else 0 for digit in bin(value)[2:]]
