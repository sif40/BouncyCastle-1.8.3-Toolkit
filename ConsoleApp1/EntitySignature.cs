using System;
using System.Collections.Generic;
using System.Text;

namespace ConsoleApp1
{
    public class EntitySignature
    {
        private IUUID _signedEntityId;
        private IUUID _signerId;
        private string _signature;

        /// <summary>
        /// Constructor.
        /// </summary>
        public EntitySignature(IUUID entity, IUUID signer, string signature) {
            _signedEntityId = entity;
            _signerId = signer;
            _signature = signature;
        }

        /// <summary>
        /// Returns the <inheritdoc cref="IUUID"/> of the signed entity as a
        /// string.
        /// </summary>
        public string SignedEntitySID => _signedEntityId.UUID.ToString();

        /// <summary>
        /// Returns the <inheritdoc cref="IUUID"/> of the signed entity.
        /// </summary>
        public IUUID SignedEntityUUID => _signedEntityId;

        /// <summary>
        /// Returns the <inheritdoc cref="IUUID"/> of the entity signer as a
        /// string.
        /// </summary>
        public string SignerSID => _signerId.UUID.ToString();

        /// <summary>
        /// Returns the <inheritdoc cref="IUUID"/> of the entity signer.
        /// </summary>
        public IUUID SignerUUID => _signerId;

        /// <summary>
        /// Returns the entity signature.
        /// </summary>
        public string Signature => _signature;
    }
}
