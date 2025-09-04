"""Config flow for OIDC Authentication integration."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import aiohttp
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import network

from .config import DOMAIN
from .oidc_client import OIDCClient, OIDCDiscoveryInvalid, OIDCJWKSInvalid

_LOGGER = logging.getLogger(__name__)

# Configuration field names
CONF_PROVIDER = "provider"
CONF_CLIENT_ID = "client_id"
CONF_CLIENT_SECRET = "client_secret"
CONF_DISCOVERY_URL = "discovery_url"
CONF_IS_CONFIDENTIAL = "is_confidential"
CONF_ENABLE_GROUPS = "enable_groups"
CONF_ADMIN_GROUP = "admin_group"
CONF_USER_GROUP = "user_group"
CONF_ENABLE_USER_LINKING = "enable_user_linking"

# Default values
DEFAULT_ADMIN_GROUP = "admins"


def _validate_discovery_url(url: str) -> bool:
    """Validate that a URL is properly formatted for OIDC discovery."""
    try:
        parsed = urlparse(url.strip())
        return bool(parsed.scheme in ("http", "https") and parsed.netloc)
    except (ValueError, TypeError):
        return False


def _sanitize_client_secret(secret: str) -> str:
    """Sanitize client secret input."""
    return secret.strip() if secret else ""


def _validate_client_id(client_id: str) -> bool:
    """Validate client ID format."""
    return bool(client_id and client_id.strip() and len(client_id.strip()) > 0)


OIDC_PROVIDERS = {
    "authentik": {
        "name": "Authentik",
        "discovery_url": "",
        "default_admin_group": DEFAULT_ADMIN_GROUP,
        "supports_groups": True,
        "claims": {
            "display_name": "name",
            "username": "preferred_username",
            "groups": "groups",
        },
    },
    "authelia": {
        "name": "Authelia",
        "discovery_url": "",
        "default_admin_group": DEFAULT_ADMIN_GROUP,
        "supports_groups": True,
        "claims": {
            "display_name": "name",
            "username": "preferred_username",
            "groups": "groups",
        },
    },
    "pocketid": {
        "name": "Pocket ID",
        "discovery_url": "",
        "default_admin_group": DEFAULT_ADMIN_GROUP,
        "supports_groups": True,
        "claims": {
            "display_name": "name",
            "username": "preferred_username",
            "groups": "groups",
        },
    },
    "kanidm": {
        "name": "Kanidm",
        "discovery_url": "",
        "default_admin_group": DEFAULT_ADMIN_GROUP,
        "supports_groups": True,
        "claims": {
            "display_name": "name",
            "username": "preferred_username",
            "groups": "groups",
        },
    },
    "microsoft": {
        "name": "Microsoft Entra ID",
        "discovery_url": (
            "https://login.microsoftonline.com/common/v2.0/"
            ".well-known/openid_configuration"
        ),
        "default_admin_group": DEFAULT_ADMIN_GROUP,
        "supports_groups": True,
        "claims": {
            "display_name": "name",
            "username": "preferred_username",
            "groups": "groups",
        },
    },
}


@dataclass
class FlowState:
    """State tracking for the configuration flow."""

    provider: str | None = None
    discovery_url: str | None = None


@dataclass
class ClientConfig:
    """Client configuration settings."""

    client_id: str | None = None
    client_secret: str | None = None
    is_confidential: bool = False


@dataclass
class FeatureConfig:
    """Feature configuration settings."""

    enable_groups: bool = False
    admin_group: str = DEFAULT_ADMIN_GROUP
    user_group: str | None = None
    enable_user_linking: bool = False


class OIDCConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for OIDC Authentication."""

    VERSION = 1

    def is_matching(self, other_flow):
        """Check if this flow is the same as another flow."""
        self_state = getattr(self, "_flow_state", None)
        other_state = getattr(other_flow, "_flow_state", None)

        if not self_state or not other_state:
            return False

        self_discovery_url = self_state.discovery_url
        other_discovery_url = other_state.discovery_url

        return (
            self_discovery_url
            and other_discovery_url
            and self_discovery_url.rstrip("/").lower()
            == other_discovery_url.rstrip("/").lower()
        )

    def __init__(self):
        """Initialize the config flow."""
        self._flow_state = FlowState()
        self._client_config = ClientConfig()
        self._feature_config = FeatureConfig()
        self._oidc_client = None
        self._oauth_state = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step - provider selection."""
        # Check if OIDC is already configured (only one instance allowed)
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        # Check if YAML configuration exists
        if self.hass.data.get(DOMAIN, {}).get("yaml_config"):
            return self.async_abort(reason="single_instance_allowed")

        errors = {}

        if user_input is not None:
            self._flow_state.provider = user_input[CONF_PROVIDER]
            provider_config = OIDC_PROVIDERS[self._flow_state.provider]

            # Set discovery URL if it's predefined
            if provider_config["discovery_url"]:
                self._flow_state.discovery_url = provider_config["discovery_url"]
                return await self.async_step_client_config()

            # For providers without predefined discovery URL, need discovery URL input
            return await self.async_step_discovery_url()

        data_schema = vol.Schema(
            {
                vol.Required(CONF_PROVIDER): vol.In(
                    {key: provider["name"] for key, provider in OIDC_PROVIDERS.items()}
                )
            }
        )

        return self.async_show_form(
            step_id="user",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={},
        )

    async def async_step_discovery_url(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle discovery URL input for providers requiring URL configuration."""
        errors = {}

        if user_input is not None:
            discovery_url = user_input[CONF_DISCOVERY_URL].rstrip("/")

            # Validate discovery URL format
            if not _validate_discovery_url(discovery_url):
                errors["discovery_url"] = "invalid_url_format"
            else:
                self._flow_state.discovery_url = discovery_url
                return await self.async_step_client_config()

        provider_name = OIDC_PROVIDERS[self._flow_state.provider]["name"]

        # Pre-populate with existing discovery URL if available
        default_url = (
            self._flow_state.discovery_url
            if self._flow_state.discovery_url
            else vol.UNDEFINED
        )

        data_schema = vol.Schema(
            {vol.Required(CONF_DISCOVERY_URL, default=default_url): str}
        )

        return self.async_show_form(
            step_id="discovery_url",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={"provider_name": provider_name},
        )

    async def async_step_client_config(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle client ID and client type selection."""
        errors = {}

        if user_input is not None:
            client_id = user_input[CONF_CLIENT_ID]

            # Validate client ID
            if not _validate_client_id(client_id):
                errors["client_id"] = "invalid_client_id"
            if not errors:
                self._client_config.client_id = client_id.strip()
                self._client_config.is_confidential = user_input.get(
                    CONF_IS_CONFIDENTIAL, False
                )

                if self._client_config.is_confidential:
                    # If confidential client, go to client secret step
                    return await self.async_step_client_secret()

                # If public client, skip to validation
                return await self.async_step_validate_connection()

        provider_name = OIDC_PROVIDERS[self._flow_state.provider]["name"]

        # Pre-populate with existing values if available
        default_client_id = (
            self._client_config.client_id
            if self._client_config.client_id
            else vol.UNDEFINED
        )
        default_is_confidential = self._client_config.is_confidential

        data_schema = vol.Schema(
            {
                vol.Required(CONF_CLIENT_ID, default=default_client_id): str,
                vol.Optional(
                    CONF_IS_CONFIDENTIAL, default=default_is_confidential
                ): bool,
            }
        )

        return self.async_show_form(
            step_id="client_config",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={
                "provider_name": provider_name,
                "discovery_url": self._flow_state.discovery_url,
            },
        )

    async def async_step_client_secret(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle client secret input for confidential clients."""
        errors = {}

        if user_input is not None:
            client_secret = user_input.get(CONF_CLIENT_SECRET, "")

            # Sanitize and validate client secret
            client_secret = _sanitize_client_secret(client_secret)
            if not client_secret:
                errors["client_secret"] = "client_secret_required"
            else:
                self._client_config.client_secret = client_secret
                return await self.async_step_validate_connection()

        provider_name = OIDC_PROVIDERS[self._flow_state.provider]["name"]

        # Pre-populate with existing client secret if available
        default_client_secret = (
            self._client_config.client_secret
            if self._client_config.client_secret
            else vol.UNDEFINED
        )

        data_schema = vol.Schema(
            {vol.Required(CONF_CLIENT_SECRET, default=default_client_secret): str}
        )

        return self.async_show_form(
            step_id="client_secret",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={
                "provider_name": provider_name,
                "client_id": self._client_config.client_id,
                "discovery_url": self._flow_state.discovery_url,
            },
        )

    async def async_step_validate_connection(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Validate the OIDC configuration by testing discovery and JWKS."""
        errors = {}

        # Handle user input from validation form
        if user_input is not None:
            action = user_input.get("action")

            if action == "retry":
                # User wants to retry validation - continue with validation logic below
                pass
            elif action == "fix_discovery":
                # User wants to fix discovery URL - return to discovery step
                return await self.async_step_discovery_url()
            elif action == "fix_client":
                # User wants to fix client settings - return to client config
                return await self.async_step_client_config()
            elif action == "change_provider":
                # User wants to change provider - return to provider selection
                return await self.async_step_user()

        # Perform validation (either initial attempt or retry)
        try:
            # Create a test OIDC client to validate configuration
            test_client = OIDCClient(
                hass=self.hass,
                discovery_url=self._flow_state.discovery_url,
                client_id=self._client_config.client_id,
                scope="openid profile",
                client_secret=self._client_config.client_secret
                if self._client_config.is_confidential
                else None,
                features={},
                claims={},
                roles={},
                network={},
            )

            # Test discovery document fetch
            discovery_doc = await test_client.validate_discovery()

            # Test JWKS retrieval
            if "jwks_uri" in discovery_doc:
                await test_client.validate_jwks(discovery_doc["jwks_uri"])

            # Store the client for later use
            self._oidc_client = test_client

            # Check if provider supports groups
            provider_config = OIDC_PROVIDERS[self._flow_state.provider]
            if provider_config["supports_groups"]:
                return await self.async_step_groups_config()

            return await self.async_step_user_linking()

        except OIDCDiscoveryInvalid:
            errors["base"] = "discovery_invalid"
        except OIDCJWKSInvalid:
            errors["base"] = "jwks_invalid"
        except aiohttp.ClientError:
            errors["base"] = "cannot_connect"
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected error during validation")
            errors["base"] = "unknown"

        # Show validation form with error and action options
        action_options = {
            "retry": "Retry Validation",
            "fix_client": "Fix Client Settings",
        }

        # Add discovery URL fix option for providers without predefined URLs
        if self._flow_state.provider in ["authelia", "authentik"]:
            action_options["fix_discovery"] = "Fix Discovery URL"

        # Add provider change option
        action_options["change_provider"] = "Change Provider"

        data_schema = vol.Schema({vol.Required("action"): vol.In(action_options)})

        return self.async_show_form(
            step_id="validate_connection",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={
                "discovery_url": self._flow_state.discovery_url,
                "client_id": self._client_config.client_id,
                "provider_name": OIDC_PROVIDERS[self._flow_state.provider]["name"],
            },
        )

    async def async_step_groups_config(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Configure groups and roles."""
        errors = {}

        if user_input is not None:
            self._feature_config.enable_groups = user_input.get(
                CONF_ENABLE_GROUPS, False
            )
            if self._feature_config.enable_groups:
                self._feature_config.admin_group = user_input.get(
                    CONF_ADMIN_GROUP, "admins"
                )
                self._feature_config.user_group = user_input.get(CONF_USER_GROUP)

            return await self.async_step_user_linking()

        provider_config = OIDC_PROVIDERS[self._flow_state.provider]
        default_admin_group = provider_config.get("default_admin_group", "admins")

        data_schema_dict = {vol.Optional(CONF_ENABLE_GROUPS, default=True): bool}

        # Add group configuration fields if groups are enabled
        if user_input is None or user_input.get(CONF_ENABLE_GROUPS, True):
            data_schema_dict.update(
                {
                    vol.Optional(CONF_ADMIN_GROUP, default=default_admin_group): str,
                    vol.Optional(CONF_USER_GROUP): str,
                }
            )

        data_schema = vol.Schema(data_schema_dict)

        return self.async_show_form(
            step_id="groups_config",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={
                "provider_name": OIDC_PROVIDERS[self._flow_state.provider]["name"]
            },
        )

    async def async_step_user_linking(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Configure user linking options."""
        errors = {}

        if user_input is not None:
            self._feature_config.enable_user_linking = user_input.get(
                CONF_ENABLE_USER_LINKING, False
            )
            return await self.async_step_test_auth()

        data_schema = vol.Schema(
            {vol.Optional(CONF_ENABLE_USER_LINKING, default=False): bool}
        )

        return self.async_show_form(
            step_id="user_linking",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={},
        )

    async def async_step_test_auth(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Test authentication flow with combined instructions."""
        if user_input is not None:
            # User has chosen to continue or skip
            return await self.async_step_finalize()

        # Generate the OAuth test URL for display
        auth_url = await self._generate_oauth_test_url()

        # Get redirect URI for display
        try:
            base_url = network.get_url(
                self.hass,
                prefer_external=True,
                allow_internal=True,
                allow_external=True,
            )
            redirect_uri = f"{base_url}/auth/oidc/callback"
        except network.NoURLAvailableError:
            redirect_uri = "Unable to determine redirect URI"

        data_schema = vol.Schema({vol.Optional("test_completed", default=True): bool})

        return self.async_show_form(
            step_id="test_auth",
            data_schema=data_schema,
            description_placeholders={
                "provider_name": OIDC_PROVIDERS[self._flow_state.provider]["name"],
                "auth_url": auth_url or "Unable to generate test URL",
                "redirect_uri": redirect_uri,
            },
        )

    async def _generate_oauth_test_url(self) -> str | None:
        """Generate OAuth test URL for manual testing."""
        try:
            # Generate a state parameter for this flow
            self._oauth_state = secrets.token_urlsafe(32)

            # Get Home Assistant base URL using the proper network helper
            # Prefer external URLs (FQDN) over internal IPs for OAuth redirects
            try:
                base_url = network.get_url(
                    self.hass,
                    prefer_external=True,
                    allow_internal=True,
                    allow_external=True,
                )
            except network.NoURLAvailableError:
                _LOGGER.warning(
                    "Unable to determine Home Assistant URL for OAuth redirect"
                )
                return None

            # Construct redirect URI using the OIDC integration's callback path
            redirect_uri = f"{base_url}/auth/oidc/callback"

            # Get authorization URL from OIDC client
            auth_url = await self._oidc_client.async_get_authorization_url(redirect_uri)

            if auth_url:
                _LOGGER.debug("Generated OAuth test URL for provider validation")
            else:
                _LOGGER.warning("Failed to generate OAuth authorization URL")

            return auth_url

        except (aiohttp.ClientError, ValueError, KeyError) as e:
            _LOGGER.error("Error generating OAuth test URL: %s", str(e))
            return None
        except Exception as e:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected error generating OAuth test URL: %s", str(e))
            return None

    async def async_step_finalize(self) -> FlowResult:
        """Finalize the configuration and create the config entry."""
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()

        provider_config = OIDC_PROVIDERS[self._flow_state.provider]

        # Build the configuration
        config_data = {
            "provider": self._flow_state.provider,
            "client_id": self._client_config.client_id,
            "discovery_url": self._flow_state.discovery_url,
            "display_name": f"{provider_config['name']} (OIDC)",
        }

        # Add optional fields
        if self._client_config.is_confidential and self._client_config.client_secret:
            config_data["client_secret"] = self._client_config.client_secret

        # Configure features
        features = {
            "automatic_user_linking": self._feature_config.enable_user_linking,
            "automatic_person_creation": True,
            "include_groups_scope": self._feature_config.enable_groups,
        }
        config_data["features"] = features

        # Configure claims using provider defaults
        claims = provider_config["claims"].copy()
        config_data["claims"] = claims

        # Configure roles if groups are enabled
        if self._feature_config.enable_groups:
            roles = {}
            if self._feature_config.admin_group:
                roles["admin"] = self._feature_config.admin_group
            if self._feature_config.user_group:
                roles["user"] = self._feature_config.user_group
            config_data["roles"] = roles

        title = f"{provider_config['name']} OIDC"

        return self.async_create_entry(title=title, data=config_data)

    async def _validate_reconfigure_input(
        self, entry, user_input: dict[str, Any]
    ) -> tuple[dict[str, str], dict[str, Any] | None]:
        """Validate reconfigure input and return errors and data updates."""
        errors = {}

        # Validate client ID
        client_id = user_input[CONF_CLIENT_ID].strip()
        if not _validate_client_id(client_id):
            errors["client_id"] = "invalid_client_id"
            return errors, None

        is_confidential = user_input.get(CONF_IS_CONFIDENTIAL, False)
        client_secret = None

        if is_confidential:
            client_secret = user_input.get(CONF_CLIENT_SECRET, "").strip()
            # If secret is empty, keep the existing one (if any)
            if not client_secret:
                client_secret = entry.data.get("client_secret")
            if not client_secret:
                errors["client_secret"] = "client_secret_required"
                return errors, None

        # Test the new configuration
        test_client = OIDCClient(
            hass=self.hass,
            discovery_url=entry.data["discovery_url"],
            client_id=client_id,
            scope="openid profile",
            client_secret=client_secret if is_confidential else None,
            features={},
            claims={},
            roles={},
            network={},
        )

        # Validate the new credentials
        discovery_doc = await test_client.validate_discovery()
        if "jwks_uri" in discovery_doc:
            await test_client.validate_jwks(discovery_doc["jwks_uri"])

        # Build updated data
        data_updates = {"client_id": client_id}

        if is_confidential and client_secret:
            data_updates["client_secret"] = client_secret
        elif "client_secret" in entry.data and not is_confidential:
            # Remove client secret if switching from confidential to public
            data_updates = {**entry.data, **data_updates}
            data_updates.pop("client_secret", None)

        return errors, data_updates

    def _build_reconfigure_schema(
        self, current_data: dict[str, Any], user_input: dict[str, Any] | None
    ) -> vol.Schema:
        """Build the reconfigure form schema."""
        current_is_confidential = bool(current_data.get("client_secret"))

        schema_dict = {
            vol.Required(
                CONF_CLIENT_ID, default=current_data.get("client_id", vol.UNDEFINED)
            ): str,
            vol.Optional(CONF_IS_CONFIDENTIAL, default=current_is_confidential): bool,
        }

        # Add client secret field if confidential client is selected
        if user_input is None or user_input.get(
            CONF_IS_CONFIDENTIAL, current_is_confidential
        ):
            schema_dict[vol.Optional(CONF_CLIENT_SECRET)] = str

        return vol.Schema(schema_dict)

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle reconfiguration of OIDC client credentials."""
        errors = {}
        entry = self._get_reconfigure_entry()

        if user_input is not None:
            try:
                errors, data_updates = await self._validate_reconfigure_input(
                    entry, user_input
                )

                if not errors:
                    # Update the config entry
                    await self.async_set_unique_id(entry.unique_id)
                    self._abort_if_unique_id_mismatch()

                    return self.async_update_reload_and_abort(
                        entry, data_updates=data_updates
                    )

            except OIDCDiscoveryInvalid:
                errors["base"] = "discovery_invalid"
            except OIDCJWKSInvalid:
                errors["base"] = "jwks_invalid"
            except aiohttp.ClientError:
                errors["base"] = "cannot_connect"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected error during reconfiguration")
                errors["base"] = "unknown"

        # Show form
        current_data = entry.data
        data_schema = self._build_reconfigure_schema(current_data, user_input)

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={
                "provider_name": OIDC_PROVIDERS.get(
                    current_data.get("provider", "authentik"), {}
                ).get("name", "Unknown Provider"),
                "discovery_url": current_data.get("discovery_url", ""),
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        return OIDCOptionsFlowHandler(config_entry)


class OIDCOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for OIDC Authentication."""

    def __init__(self, config_entry):
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """Handle options flow."""
        if user_input is not None:
            # Process the updated configuration
            updated_features = {
                "automatic_user_linking": user_input.get("enable_user_linking", False),
                "include_groups_scope": user_input.get("enable_groups", False),
            }

            updated_roles = {}
            if user_input.get("enable_groups", False):
                if user_input.get("admin_group"):
                    updated_roles["admin"] = user_input["admin_group"]
                if user_input.get("user_group"):
                    updated_roles["user"] = user_input["user_group"]

            # Update the config entry data
            new_data = self.config_entry.data.copy()
            new_data["features"] = {**new_data.get("features", {}), **updated_features}
            if updated_roles:
                new_data["roles"] = updated_roles
            elif "roles" in new_data:
                # Remove roles if groups are disabled
                if not user_input.get("enable_groups", False):
                    del new_data["roles"]

            # Update the config entry
            self.hass.config_entries.async_update_entry(
                self.config_entry, data=new_data
            )

            return self.async_create_entry(title="", data={})

        current_config = self.config_entry.data
        current_features = current_config.get("features", {})
        current_roles = current_config.get("roles", {})

        # Determine if this provider supports groups
        provider = current_config.get("provider", "authentik")
        provider_supports_groups = OIDC_PROVIDERS.get(provider, {}).get(
            "supports_groups", True
        )

        # Build schema based on provider capabilities
        schema_dict = {
            vol.Optional(
                "enable_user_linking",
                default=current_features.get("automatic_user_linking", False),
            ): bool
        }

        # Add groups options if provider supports them
        if provider_supports_groups:
            enable_groups_default = current_features.get("include_groups_scope", False)
            schema_dict[
                vol.Optional("enable_groups", default=enable_groups_default)
            ] = bool

            # Add group name fields if groups are currently enabled or being enabled
            if enable_groups_default or (
                user_input and user_input.get("enable_groups", False)
            ):
                schema_dict.update(
                    {
                        vol.Optional(
                            "admin_group",
                            default=current_roles.get("admin", DEFAULT_ADMIN_GROUP),
                        ): str,
                        vol.Optional(
                            "user_group", default=current_roles.get("user", "")
                        ): str,
                    }
                )

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(schema_dict),
            description_placeholders={
                "provider_name": OIDC_PROVIDERS.get(provider, {}).get(
                    "name", provider.title()
                )
            },
        )
