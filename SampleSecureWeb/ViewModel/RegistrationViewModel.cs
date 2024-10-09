using System;
using System.ComponentModel.DataAnnotations;

namespace SampleSecureWeb.ViewModel;

public class RegistrationViewModel
{
    [Required]
    public string? Username { get; set;}
    
    [Required]
    [DataType(DataType.Password)]
    public string? Password { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [MinLength(12, ErrorMessage = "The password must be at least 12 characters long.")]
    [RegularExpression(@"(?=.*[!@#$%^&*(),.?""{}|<>])[A-Za-z\d!@#$%^&*(),.?""{}|<>]{12,}$",ErrorMessage = "The password must have special character")]
    [Display(Name = "Confirm Password")]
    [Compare("Password",ErrorMessage ="The Password and confirmation Password do not match")]
    public string? ConfirmPassword { get; set;}

}
