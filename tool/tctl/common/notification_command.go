/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package common

import (
	"context"
	"fmt"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/gravitational/teleport"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	notificationspb "github.com/gravitational/teleport/api/gen/proto/go/teleport/notifications/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/service/servicecfg"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
)

// NotificationCommand implements the `tctl notifications` family of commands.
type NotificationCommand struct {
	ls  *kingpin.CmdClause
	rm  *kingpin.CmdClause
	add *kingpin.CmdClause

	format string
	user   string
	global bool

	title string
	desc  string
}

// Initialize allows ACLCommand to plug itself into the CLI parser
func (n *NotificationCommand) Initialize(app *kingpin.Application, _ *servicecfg.Config) {
	not := app.Command("notification", "Manage cluster notifications.")

	n.add = not.Command("add", "Create a cluster notification.").Alias("create")
	n.add.Flag("user", "Target a specific user.").StringVar(&n.user)
	n.add.Flag("global", "Target all users.").Short('g').BoolVar(&n.global) // TODO: consider making global default if --user is empty
	n.add.Flag("title", "Set the notification's title").Short('t').Required().StringVar(&n.title)
	n.add.Flag("description", "Set the notification's description").StringVar(&n.desc)

	n.ls = not.Command("ls", "List cluster notifications.")
	n.ls.Flag("format", "Output format, 'yaml', 'json', or 'text'").Default(teleport.Text).EnumVar(&n.format, teleport.YAML, teleport.JSON, teleport.Text)

	n.rm = not.Command("rm", "Remove a cluster notification.")
	n.rm.Flag("user", "Remove a user-specific notification.").StringVar(&n.user)
	n.rm.Arg("id", "The ID of the notification to remove.").Required().StringVar(&n.title)
}

// TryRun takes the CLI command as an argument and executes it.
func (n *NotificationCommand) TryRun(ctx context.Context, cmd string, client *auth.Client) (match bool, err error) {
	nc := client.NotificationsClient()

	switch cmd {
	case n.add.FullCommand():
		err = n.Add(ctx, nc)
	case n.ls.FullCommand():
		err = n.List(ctx, nc)
	case n.rm.FullCommand():
		err = n.Remove(ctx, nc)
	default:
		return false, nil
	}
	return true, trace.Wrap(err)
}

// Add creates a new notification.
func (n *NotificationCommand) Add(ctx context.Context, client notificationspb.NotificationServiceClient) error {
	if n.global != (n.user != "") {
		return trace.BadParameter("exactly one of --global or --user must be specified")
	}

	meta := &headerv1.Metadata{
		Description: "User-defined notification",
		Labels: map[string]string{
			// TODO: make constants for these label keys
			"teleport.internal/notification-title": n.title,
			"teleport.internal/notification-desc":  n.desc,
		},
	}

	notification := &notificationspb.Notification{
		Kind:     types.KindNotification,
		Metadata: meta,
		Spec:     &notificationspb.NotificationSpec{},
	}

	if n.global {
		_, err := client.CreateGlobalNotification(ctx, &notificationspb.CreateGlobalNotificationRequest{
			GlobalNotification: &notificationspb.GlobalNotification{
				Kind: types.KindGlobalNotification,
				Spec: &notificationspb.GlobalNotificationSpec{
					Matcher:      nil, // TODO: all
					Notification: notification,
				},
			},
		})

		return trail.FromGRPC(err)
	}

	_, err := client.CreateUserNotification(ctx, &notificationspb.CreateUserNotificationRequest{
		Username:     n.user,
		Notification: notification,
	})

	// TODO: consider printing ID of newly-created notification
	return trail.FromGRPC(err)
}

func (n *NotificationCommand) List(ctx context.Context, client notificationspb.NotificationServiceClient) error {
	var result []*notificationspb.Notification
	var pageToken string
	for {
		resp, err := client.ListUserNotifications(ctx, &notificationspb.ListUserNotificationsRequest{
			// TODO:
			// 1) check that RBAC works correctly and that one user cannot see another user's notifications
			// 2) check that we can list only global notifications by omitting the --user flag
			Username:  n.user,
			PageSize:  512,
			PageToken: pageToken,
		})
		if err != nil {
			return trace.Wrap(err)
		}
		result = append(result, resp.Notifications...)
		pageToken = resp.GetNextPageToken()
		if pageToken == "" {
			break
		}
	}

	// TODO: consider sort options here

	displayNotifications(n.format, result)
	return nil
}

func displayNotifications(format string, notifications []*notificationspb.Notification) {
	switch format {
	case teleport.Text:
		table := asciitable.MakeTable([]string{"ID", "Created", "Expires", "Title"})
		for _, n := range notifications {
			table.AddRow([]string{
				n.GetMetadata().GetName(),
				"",
				n.GetMetadata().GetExpires().String(), // TODO: format time.RFC822
				n.GetMetadata().GetLabels()["teleport.dev/notification-title"], // TODO: truncate?
			})
		}
		fmt.Println(table.AsBuffer().String())
	case teleport.JSON:
		utils.WriteJSONArray(os.Stdout, notifications)
	case teleport.YAML:
		utils.WriteYAML(os.Stdout, notifications)
	default:
		// do nothing, kingpin validates the --format flag before we ever get here
	}
}

// Remove removes a notification.
func (n *NotificationCommand) Remove(ctx context.Context, client notificationspb.NotificationServiceClient) error {
	var err error
	switch {
	case n.user != "":
		_, err = client.DeleteUserNotification(ctx, &notificationspb.DeleteUserNotificationRequest{
			Username:       n.user,
			NotificationId: n.title,
		})
		// TODO: clean up related entities (last seen, notification state, etc)

	default:
		_, err = client.DeleteGlobalNotification(ctx, &notificationspb.DeleteGlobalNotificationRequest{
			NotificationId: n.title,
		})
	}

	return trail.FromGRPC(err)
}
