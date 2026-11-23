// Package oxide reads what the attestor needs from the Oxide API.
package oxide

import (
	"context"
	"errors"
	"fmt"

	"github.com/oxidecomputer/oxide.go/oxide"

	"github.com/bwagner5/ox-node-attestor/pkg/server"
)

// Client reads the Oxide API with the credential in OXIDE_HOST and
// OXIDE_TOKEN.
type Client struct {
	api *oxide.Client
}

func New() (*Client, error) {
	api, err := oxide.NewClient()
	if err != nil {
		return nil, err
	}
	return &Client{api: api}, nil
}

// Policy resolves a project, by name or ID, to the IDs attestations carry:
// the project's and the silo's the credential belongs to.
func (c *Client) Policy(ctx context.Context, project string) (server.Policy, error) {
	user, err := c.api.CurrentUserView(ctx)
	if err != nil {
		return server.Policy{}, fmt.Errorf("reading the Oxide credential's silo: %w", err)
	}
	p, err := c.api.ProjectView(ctx, oxide.ProjectViewParams{Project: oxide.NameOrId(project)})
	if err != nil {
		return server.Policy{}, fmt.Errorf("reading project %q: %w", project, err)
	}
	return server.Policy{SiloID: user.SiloId, ProjectID: p.Id}, nil
}

func (c *Client) Instance(ctx context.Context, id string) (*server.Instance, error) {
	instance, err := c.api.InstanceView(ctx, oxide.InstanceViewParams{Instance: oxide.NameOrId(id)})
	if errors.Is(err, oxide.ErrObjectNotFound) || errors.Is(err, oxide.ErrHTTP404) {
		return nil, server.ErrInstanceNotFound
	}
	if err != nil {
		return nil, err
	}
	return &server.Instance{
		ID:        instance.Id,
		ProjectID: instance.ProjectId,
		Hostname:  instance.Hostname,
		Running:   instance.RunState == oxide.InstanceStateRunning,
	}, nil
}
