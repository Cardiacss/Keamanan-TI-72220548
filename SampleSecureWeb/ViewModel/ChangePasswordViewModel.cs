using System;

namespace SampleSecureWeb.ViewModel;
using System.ComponentModel.DataAnnotations;

public class ChangePasswordViewModel
{
    [Required(ErrorMessage = "Current password is required.")]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "New password is required.")]
        [DataType(DataType.Password)]
        [MinLength(12, ErrorMessage = "The password must be at least 12 characters long.")]
        [RegularExpression(@"(?=.[A-Z])(?=.[a-z])(?=.\d)(?=.[!@#$%^&(),.?""{}|<>])[A-Za-z\d!@#$%^&(),.?""{}|<>]{12,}$", 
            ErrorMessage = "The password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.")]
        public string NewPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please confirm your new password.")]
        [DataType(DataType.Password)]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmNewPassword { get; set; } = string.Empty;
}
