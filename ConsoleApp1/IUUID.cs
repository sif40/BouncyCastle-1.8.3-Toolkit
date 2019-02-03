using System;
using System.Collections.Generic;
using System.Text;

namespace ConsoleApp1
{
    public interface IUUID
    {
        /// <summary>
        /// Is a unique random value, unambiguously identifying the respective
        /// entity. Use the <see cref="UUIDTester"/> utility class to check
        /// all tenant repos for an existing occurrence of the specified value.
        /// </summary>
        Guid UUID {
            get;
        }
    }
}
