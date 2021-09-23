using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace KeweenawCheeseSite.Data
{
    public class DiscordUser
    {
        [Key]
        [Column("Id", TypeName = "bigint")]
        public Int64 Id { get; set; }

        [Column("UserName", TypeName = "nvarchar(256)")]
        public string DisplayName { get; set; }

        [Column("Discriminator", TypeName = "nvarchar(128)")]
        public string Discriminator { get; set; }

        [Column("Avatar", TypeName = "nvarchar(1024)")]
        public string Avatar { get; set; }
    }
}
