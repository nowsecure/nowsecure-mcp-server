package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerPlatformPrompts adds short, user-selectable workflow starters. They
// describe an outcome and let the model choose the tool-call details.
func registerPlatformPrompts(server *mcp.Server) {
	addWorkflowPrompt(server, &mcp.Prompt{
		Name:        "platform_triage_portfolio",
		Title:       "Triage my app portfolio",
		Description: "Prioritize the riskiest first-party apps and their remediation work.",
	}, func(map[string]string) (string, error) {
		return "Review my NowSecure Platform portfolio. Start with list_apps, prioritize the lowest scores and most severe findings, then summarize the highest-risk apps and next remediation actions. Include app_ref and finding keys in the result.", nil
	})

	addWorkflowPrompt(server, &mcp.Prompt{
		Name:        "platform_review_app",
		Title:       "Review a Platform app",
		Description: "Review the latest scan and affected findings for one app.",
		Arguments: []*mcp.PromptArgument{{
			Name:        "app",
			Title:       "App",
			Description: "App title, package, app_ref, or NowSecure URL",
			Required:    true,
		}},
	}, func(args map[string]string) (string, error) {
		app, err := requiredPromptArgument(args, "app")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Review the latest NowSecure Platform results for %s. Resolve it with decode_nowsecure_url or list_apps, inspect its latest scan and affected findings, and summarize risk plus prioritized remediation. Include the app_ref, assessment_ref, and finding keys.", app), nil
	})

	addWorkflowPrompt(server, &mcp.Prompt{
		Name:        "platform_investigate_finding",
		Title:       "Investigate fleet-wide finding impact",
		Description: "Find affected apps and remediation guidance for a security finding.",
		Arguments: []*mcp.PromptArgument{{
			Name:        "finding",
			Title:       "Finding",
			Description: "Finding key, title, topic, or NowSecure URL",
			Required:    true,
		}},
	}, func(args map[string]string) (string, error) {
		finding, err := requiredPromptArgument(args, "finding")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Assess the fleet-wide impact of the NowSecure Platform finding %s. Resolve its key with decode_nowsecure_url or search_findings, list affected apps, prioritize them by app risk, and summarize remediation from get_finding.", finding), nil
	})
}

func registerMARIPrompts(server *mcp.Server) {
	addWorkflowPrompt(server, &mcp.Prompt{
		Name:        "mari_triage_catalog",
		Title:       "Triage my third-party app catalog",
		Description: "Prioritize third-party apps that need vendor-risk review.",
	}, func(map[string]string) (string, error) {
		return "Review my NowSecure MARI catalog. Use list_mari_apps to prioritize HIGH-risk and high-risk-score third-party apps, then summarize which vendors need deeper review and why. Remember that a higher MARI risk score is worse.", nil
	})

	addWorkflowPrompt(server, &mcp.Prompt{
		Name:        "mari_review_app",
		Title:       "Vet a third-party app",
		Description: "Review one third-party app's MARI risk profile.",
		Arguments: []*mcp.PromptArgument{{
			Name:        "app",
			Title:       "App",
			Description: "App title, package, assessment_ref, or NowSecure URL",
			Required:    true,
		}},
	}, func(args map[string]string) (string, error) {
		app, err := requiredPromptArgument(args, "app")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Vet this third-party app in NowSecure MARI: %s. Locate its assessment, summarize its risk score, rating, category, and severe findings, then inspect only the relevant permissions, trackers, SDKs, network, or AI-usage sections. State any data gaps.", app), nil
	})

	addWorkflowPrompt(server, &mcp.Prompt{
		Name:        "mari_compare_apps",
		Title:       "Compare third-party apps",
		Description: "Compare the risk profiles of two or more third-party apps.",
		Arguments: []*mcp.PromptArgument{{
			Name:        "apps",
			Title:       "Apps",
			Description: "Comma-separated app titles, packages, assessment refs, or NowSecure URLs",
			Required:    true,
		}},
	}, func(args map[string]string) (string, error) {
		apps, err := requiredPromptArgument(args, "apps")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Compare these third-party apps in NowSecure MARI: %s. Compare risk score, rating, category, severe findings, and relevant expanded signals; recommend the safer choice and state any missing or non-comparable data.", apps), nil
	})
}

func addWorkflowPrompt(server *mcp.Server, prompt *mcp.Prompt, render func(map[string]string) (string, error)) {
	server.AddPrompt(prompt, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		text, err := render(req.Params.Arguments)
		if err != nil {
			return nil, err
		}
		return &mcp.GetPromptResult{
			Description: prompt.Description,
			Messages: []*mcp.PromptMessage{{
				Role:    "user",
				Content: &mcp.TextContent{Text: text},
			}},
		}, nil
	})
}

func requiredPromptArgument(args map[string]string, name string) (string, error) {
	value := strings.TrimSpace(args[name])
	if value == "" {
		return "", fmt.Errorf("prompt argument %q is required", name)
	}
	return value, nil
}
