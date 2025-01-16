using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models.ViewModels.LoginVM
{
    public class ForgetPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
       
    }
}
