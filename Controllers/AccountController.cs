using AuthenticationServize.Domain.Repository;
using Core.Library;
using Core.Library.HttpContextData;
using Makaan.DTO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Makaan.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {


        private readonly AccountRepository _repository;

        public AccountController(AccountRepository repository)
        {
            _repository = repository;

        }


        [HttpPost]
        [Route("register")]
        [Produces("application/json")]
        [Consumes("application/json")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AuthSuccessResponse>> Register([FromBody] RegistrationInputRequest model)
        {
            Response<AuthSuccessResponse> response = await _repository.AddUserToIdentityWithSpecificRoles(model);
            if (response.IsSuccessStatusCode())
            {
                return Ok(response.Resource);
            }
            return Problem(statusCode: response.StatusCode, detail: response.Message);
        }

        [HttpPost("refreshToken")]
        [Produces("application/json")]
        [Consumes("application/json")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AuthSuccessResponse>> RefreshToken([FromBody] RefreshTokenRequest refreshRequest)
        {
            var val = AuthenticationPrincipals.GetLoginUserId(HttpContext.User);
            Response<AuthSuccessResponse> response = await _repository.RefreshTokenAsync(refreshRequest.RefreshToken);
            if (response.IsSuccessStatusCode())
            {
                return Ok(response.Resource);
            }
            return Problem(detail: response.Message, statusCode: response.StatusCode);
        }
        [HttpPost("login")]
        [Produces("application/json")]
        [Consumes("application/json")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<AuthSuccessResponse>> Login([FromBody] InputLoginModel model)
        {
            Response<AuthSuccessResponse> response = await _repository.HandleLoginRequest(model);
            if (response.IsSuccessStatusCode())
                return Ok(response.Resource);
            return Problem(detail: response.Message, statusCode: response.StatusCode);
        }
    }
}
