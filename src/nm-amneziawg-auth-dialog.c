/*
 * nm-amneziawg-auth-dialog: minimal old-style VPN auth helper for AmneziaWG.
 *
 * NetworkManager's secret agent (gnome-shell's ShellNetworkAgent) launches
 * the binary referenced by the [GNOME] auth-dialog key of
 * nm-amneziawg-service.name when it needs to (re)collect VPN secrets, e.g.
 * when nm-connection-editor opens an AmneziaWG connection:
 *
 *     nm-amneziawg-auth-dialog -u <uuid> -n <name> -s <service>
 *                              [-i] [-r] [-t <hint>]...
 *
 * The agent then writes the current VPN data items and secrets to our
 * standard input:
 *
 *     DATA_KEY=<key>
 *     DATA_VAL=<value>
 *     <blank line>
 *     SECRET_KEY=<key>
 *     SECRET_VAL=<value>
 *     <blank line>
 *     DONE
 *     <blank line>
 *
 * and reads our standard output: every pair of lines "key\nvalue" is stored
 * as a VPN secret of the connection, and the list ends with an empty line.
 * Once it has seen that empty line the agent sends "QUIT" on standard input
 * and treats our exit as the end of the request, so we must stay alive until
 * QUIT arrives: exiting right after printing makes the agent answer
 * INTERNAL_ERROR with no secrets.  Exiting with status 0 confirms the reply;
 * a non-zero status cancels the request.
 *
 * AmneziaWG requires exactly one interface secret: the private key
 * (local-private-key).  Per-peer preshared keys are optional.  There is
 * nothing to ask the user for, so we echo every secret we were given back
 * unchanged and exit 0.  The echo is required: with an empty reply the
 * editors open with empty private and preshared key fields.  A missing or
 * invalid private key is only logged: failing a plain lookup (the editors
 * opening a connection) would make GetSecrets fail and the editor would lose
 * the secrets NetworkManager has stored.  Only if the agent asked for
 * interaction (-i) or new secrets (-r), which we cannot provide, do we exit 1
 * so the agent gives up instead of waiting forever.
 *
 * NOTE: unlike the full auth dialogs of other VPN plugins (for example
 * nm-openvpn-auth-dialog), this helper does not prompt the user with a GUI.
 * Connections whose private key is stored with the "ask every time" secret
 * flag therefore cannot be connected through the agent; the key has to be
 * set through nm-connection-editor (which stores it) first.
 */

#include <gio/gio.h>
#include <gio/gunixinputstream.h>
#include <glib.h>
#include <glib/gi18n.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define AWG_PRIVATE_KEY "local-private-key"
#define AWG_KEY_SIZE 32

static const char *opt_uuid = NULL;
static const char *opt_name = NULL;
static const char *opt_service = NULL;
static gboolean opt_interactive = FALSE;
static gboolean opt_request_new = FALSE;
static gchar **opt_hints = NULL;

/*
 * Validate that @value is a base64-encoded key of exactly AWG_KEY_SIZE bytes.
 */
static gboolean
is_valid_private_key(const char *value)
{
    g_autofree guchar *decoded = NULL;
    gsize length = 0;

    if (!value || !*value) {
        return FALSE;
    }

    decoded = g_base64_decode(value, &length);
    if (!decoded) {
        return FALSE;
    }

    return length == AWG_KEY_SIZE;
}

/*
 * Read the connection data written by the secret agent on standard input.
 *
 * Returns: %TRUE if a valid local-private-key was received.
 */
static gboolean
read_secrets_from_stdin(GString *reply)
{
    GDataInputStream *din;
    /* Keep fd 0 open: wait_for_quit() still reads it after the reply. */
    GInputStream *in = g_unix_input_stream_new(STDIN_FILENO, FALSE);
    gchar *current_secret_key = NULL;
    gboolean have_valid_private_key = FALSE;
    gboolean private_key_seen = FALSE;
    gchar *line = NULL;

    if (!in) {
        return FALSE;
    }

    din = g_data_input_stream_new(in);

    while ((line = g_data_input_stream_read_line(din, NULL, NULL, NULL))) {
        gchar *stripped = g_strstrip(line);

        if (g_str_equal(stripped, "DONE")) {
            if (stripped != line) {
                g_free(stripped);
            }
            g_free(line);
            break;
        }

        if (g_str_has_prefix(stripped, "SECRET_KEY=")) {
            g_free(current_secret_key);
            current_secret_key = g_strdup(stripped + sizeof("SECRET_KEY=") - 1);
        } else if (g_str_has_prefix(stripped, "SECRET_VAL=")) {
            const char *value = stripped + sizeof("SECRET_VAL=") - 1;

            if (current_secret_key && *value) {
                g_string_append_printf(reply, "%s\n%s\n", current_secret_key, value);
            }

            if (current_secret_key &&
                g_str_equal(current_secret_key, AWG_PRIVATE_KEY)) {
                private_key_seen = TRUE;
                if (is_valid_private_key(value)) {
                    have_valid_private_key = TRUE;
                } else {
                    g_warning("Received an invalid private key "
                              "(expected base64-encoded %d bytes)",
                              AWG_KEY_SIZE);
                }
            }
        }
        /* DATA_KEY= lines and blank lines are not needed for this helper. */

        if (stripped != line) {
            g_free(stripped);
        }
        g_free(line);
    }

    g_free(current_secret_key);

    if (!private_key_seen && !have_valid_private_key) {
        g_warning("The AmneziaWG secret \"%s\" is missing or invalid; "
                  "set the private key in nm-connection-editor",
                  AWG_PRIVATE_KEY);
    }

    g_object_unref(din);
    g_object_unref(in);

    return have_valid_private_key;
}

/*
 * Block until the agent tells us it is done with our reply (or closes stdin).
 */
static void
wait_for_quit(void)
{
    char buf[64];

    while (fgets(buf, sizeof(buf), stdin)) {
        if (g_str_has_prefix(buf, "QUIT")) {
            break;
        }
    }
}

int
main(int argc, char *argv[])
{
    GOptionContext *opt_ctx;
    GError *error = NULL;
    GString *reply;
    gboolean ok;

    static GOptionEntry options[] = {
        { "uuid", 'u', 0, G_OPTION_ARG_STRING, &opt_uuid,
          N_("Connection UUID"), NULL },
        { "name", 'n', 0, G_OPTION_ARG_STRING, &opt_name,
          N_("Connection name"), NULL },
        { "service", 's', 0, G_OPTION_ARG_STRING, &opt_service,
          N_("Service type"), NULL },
        { "interactive", 'i', 0, G_OPTION_ARG_NONE, &opt_interactive,
          N_("User interaction allowed"), NULL },
        { "request-new", 'r', 0, G_OPTION_ARG_NONE, &opt_request_new,
          N_("Request new secrets"), NULL },
        { "hint", 't', 0, G_OPTION_ARG_STRING_ARRAY, &opt_hints,
          N_("Secret hint"), NULL },
        { NULL }
    };

    /*
     * gnome-shell may close the read end of our stderr pipe.  A diagnostic
     * written then would raise SIGPIPE and kill us mid-request, which the
     * shell reports as INTERNAL_ERROR.  Make such writes fail quietly.
     */
    signal(SIGPIPE, SIG_IGN);

    opt_ctx = g_option_context_new(NULL);
    g_option_context_set_translation_domain(opt_ctx, GETTEXT_PACKAGE);
    g_option_context_set_summary(
        opt_ctx, "Auth dialog helper for the AmneziaWG VPN plugin.");
    g_option_context_add_main_entries(opt_ctx, options, NULL);

    if (!g_option_context_parse(opt_ctx, &argc, &argv, &error)) {
        g_printerr("%s: %s\n", g_get_application_name(), error->message);
        g_error_free(error);
        g_option_context_free(opt_ctx);
        return EXIT_FAILURE;
    }
    g_option_context_free(opt_ctx);

    if (opt_uuid) {
        g_debug("auth-dialog for connection %s (name=%s, service=%s)%s%s",
                opt_uuid,
                opt_name ? opt_name : "?",
                opt_service ? opt_service : "?",
                opt_interactive ? ", interactive" : "",
                opt_request_new ? ", request-new" : "");
    }

    /*
     * This helper does not collect new input: it echoes the secrets the agent
     * already knows, so that callers (nm-connection-editor) still see them.
     */
    reply = g_string_new(NULL);
    ok = read_secrets_from_stdin(reply);
    if (ok || !(opt_interactive || opt_request_new)) {
        /* An empty line terminates the list of secrets. */
        g_print("%s\n\n", reply->str);
        fflush(stdout);
        wait_for_quit();
        ok = TRUE;
    }
    g_string_free(reply, TRUE);

    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
