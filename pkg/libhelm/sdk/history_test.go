package sdk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	chart "helm.sh/helm/v4/pkg/chart/v2"
	sdkrelease "helm.sh/helm/v4/pkg/release/v1"
)

func Test_ConvertHistory(t *testing.T) {
	t.Parallel()
	t.Run("successfully maps a sdk release to a release", func(t *testing.T) {
		is := assert.New(t)

		release := sdkrelease.Release{
			Name:    "releaseName",
			Version: 1,
			Info: &sdkrelease.Info{
				Status: "deployed",
			},
			Chart: &chart.Chart{
				Metadata: &chart.Metadata{
					Name:       "chartName",
					Version:    "chartVersion",
					AppVersion: "chartAppVersion",
				},
			},
		}

		result, err := convertHistory(&release)
		require.NoError(t, err)
		is.Equal(release.Name, result.Name)
	})
}
