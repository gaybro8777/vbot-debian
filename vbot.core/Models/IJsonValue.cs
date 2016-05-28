using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace vbot.core
{
    public interface IJsonValue
    {
        string Name { get; set; }
        string JsonType { get; }
    }
}
