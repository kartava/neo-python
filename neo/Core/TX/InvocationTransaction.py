from neo.Core.TX.Transaction import Transaction, TransactionType
import sys
from neo.Core.Fixed8 import Fixed8
from neo.Core.Size import GetVarSize, Size


class InvocationTransaction(Transaction):
    Script = None
    Gas = None

    def SystemFee(self):
        """
        Get the system fee.

        Returns:
            Fixed8:
        """
        return self.Gas

    def __init__(self, *args, **kwargs):
        """
        Create an instance.

        Args:
            *args:
            **kwargs:
        """
        super(InvocationTransaction, self).__init__(*args, **kwargs)
        self.Gas = Fixed8(0)
        self.Type = TransactionType.InvocationTransaction

    def Size(self):
        """
        Get the total size in bytes of the object.

        Returns:
            int: size.
        """

        sizeGas = Size.uint64 if self.Version >= 1 else 0

        return super(InvocationTransaction, self).Size() + GetVarSize(self.Script) + sizeGas

    def DeserializeExclusiveData(self, reader):
        """
        Deserialize full object.

        Args:
            reader (neo.IO.BinaryReader):

        Raises:
            Exception: If the version read is incorrect.
        """
        if self.Version > 1:
            raise Exception('Invalid format')

        self.Script = reader.ReadVarBytes()

        if len(self.Script) == 0:
            raise Exception('Invalid Format')

        if self.Version >= 1:
            self.Gas = reader.ReadFixed8()
            if self.Gas < Fixed8.Zero():
                raise Exception("Invalid Format")
        else:
            self.Gas = Fixed8(0)

    def SerializeExclusiveData(self, writer):
        """
        Serialize object.

        Args:
            writer (neo.IO.BinaryWriter):
        """
        writer.WriteVarBytes(self.Script)
        if self.Version >= 1:
            writer.WriteFixed8(self.Gas)

    def Verify(self, mempool):
        """
        Verify the transaction.

        Args:
            mempool:

        Returns:
            bool: True if verified. False otherwise.
        """
        if self.Gas.value % 100000000 != 0:
            return False
        return super(InvocationTransaction, self).Verify(mempool)

    def ToJson(self):
        """
        Convert object members to a dictionary that can be parsed as JSON.

        Returns:
             dict:
        """
        jsn = super(InvocationTransaction, self).ToJson()
        jsn['script'] = self.Script.hex()
        jsn['gas'] = self.Gas.ToNeoJsonString()
        return jsn
