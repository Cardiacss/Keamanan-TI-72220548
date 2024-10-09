using System;
using System.ComponentModel.DataAnnotations;

namespace SampleSecureWeb.ViewModel;

public class ChangePasswordViewModel
{
     [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Current Password")]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [MinLength(12, ErrorMessage = "The new password must be at least 12 characters long.")]
        [RegularExpression(@"^(?=.*[!@#$%^&*(),.?""{}|<>])[A-Za-z\d!@#$%^&*(),.?""{}|<>]{12,}$", 
            ErrorMessage = "New password must contain at least one special character.")]
        [Display(Name = "New Password")]
        public string NewPassword { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm New Password")]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmNewPassword { get; set; } = string.Empty;
}
