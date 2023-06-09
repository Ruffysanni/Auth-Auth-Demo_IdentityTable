﻿using System.ComponentModel.DataAnnotations;

namespace IdentityTable.Authentication
{
    public class LoginModel
    {
        [Required(ErrorMessage ="Username is required!")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Password is required!")]
        public string Password { get; set; }
    }
}
