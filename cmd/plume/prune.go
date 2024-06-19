// Copyright 2020 Kinvolk GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/coreos/pkg/capnslog"
	"github.com/flatcar/azure-vhd-utils/upload/metadata"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"

	"github.com/flatcar/mantle/platform/api/aws"
	"github.com/flatcar/mantle/platform/api/azure"
)

var (
	days              int
	daysSoftDeleted   int
	daysLastLaunched  int
	keepLast          int
	pruneDryRun       bool
	checkLastLaunched bool
	cmdPrune          = &cobra.Command{
		Use:   "prune --channel CHANNEL [options]",
		Short: "Prune old release images for the given channel.",
		Run:   runPrune,
		Long:  `Prune old release images for the given channel.`,
	}
)

func init() {
	cmdPrune.Flags().IntVar(&days, "days", 30, "Minimum age in days for files to get deleted")
	cmdPrune.Flags().IntVar(&daysLastLaunched, "days-last-launched", 0,
		"Minimum lastLaunchedTime value in days for images to be deleted. Only used when --check-last-launched is set. If not provided, --days value is used.")
	cmdPrune.Flags().IntVar(&daysSoftDeleted, "days-soft-deleted", 0, "Minimum age in days for files to remain soft deleted (recoverable)")
	cmdPrune.Flags().IntVar(&keepLast, "keep-last", 0, "Number of latest images to keep")
	cmdPrune.Flags().StringVar(&awsCredentialsFile, "aws-credentials", "", "AWS credentials file")
	cmdPrune.Flags().StringVar(&azureTestContainer, "azure-test-container", "", "Use another container instead of the default")
	cmdPrune.Flags().BoolVarP(&pruneDryRun, "dry-run", "n", false,
		"perform a trial run, do not make changes")
	cmdPrune.Flags().BoolVarP(&checkLastLaunched, "check-last-launched", "c", false, "Check whether image has been launched recently")
	addAzureAuthFlags(cmdPrune.Flags())
	AddSpecFlags(cmdPrune.Flags())
	root.AddCommand(cmdPrune)
}

func runPrune(cmd *cobra.Command, args []string) {
	if len(args) > 0 {
		plog.Fatal("No args accepted")
	}
	if daysLastLaunched < 0 {
		plog.Fatal("days-last-launched must be >= 0")
	}
	if daysSoftDeleted < 0 {
		plog.Fatal("days-soft-deleted must be >= 0")
	}
	if keepLast < 0 {
		plog.Fatal("keep-last must be >= 0")
	}
	if !checkLastLaunched && daysLastLaunched > 0 {
		plog.Fatal("days-last-launched is ignored when check-last-launched is not set")
	}
	if checkLastLaunched && daysLastLaunched == 0 {
		daysLastLaunched = days
	}

	// Override specVersion as it's not relevant for this command
	specVersion = "none"

	spec := ChannelSpec()
	ctx := context.Background()
	pruneAWS(ctx, &spec)
	pruneAzure(ctx, &spec)
}

func pruneAzure(ctx context.Context, spec *channelSpec) {
	if spec.Azure.StorageAccount == "" {
		plog.Notice("Azure image pruning disabled, skipping.")
		return
	}

	for _, environment := range spec.Azure.Environments {
		api, err := azure.New(&azure.Options{
			UseDefaultAuth:    azureUseDefaultAuth,
			CloudName:         environment.CloudName,
			AzureAuthLocation: azureAuth,
		})
		if err != nil {
			plog.Fatalf("Failed to create Azure API: %v", err)
		}
		if err := api.SetupClients(); err != nil {
			plog.Fatalf("Failed to set up clients: %v", err)
		}

		client, err := api.GetBlobServiceClient(spec.Azure.StorageAccount)
		if err != nil {
			plog.Fatalf("failed to create blob service client for %q: %v", spec.Azure.StorageAccount, err)
		}

		containerName := spec.Azure.Container
		if azureTestContainer != "" {
			containerName = azureTestContainer
		}

		// Remove the compression extension from the filename, as Azure sets
		// the filename without the compression extension.
		specFileName := strings.TrimSuffix(spec.Azure.Image, filepath.Ext(spec.Azure.Image))

		blobs, err := azure.ListBlobs(client, containerName, container.ListBlobsInclude{Metadata: true})
		if err != nil {
			plog.Warningf("Error listing blobs: %v", err)
		}
		plog.Infof("Got %d blobs for container %q", len(blobs), containerName)

		now := time.Now()
		for _, blob := range blobs {
			// Check that the blob's name includes the channel
			if !strings.Contains(*blob.Name, specChannel) {
				plog.Infof("Blob's name %q doesn't include %q, skipping.", *blob.Name, specChannel)
				continue
			}
			// Get the blob metadata and check that it's one of the release images
			metadata, err := metadata.NewMetadataFromBlobMetadata(blob.Metadata)
			if err != nil {
				plog.Infof("Failed to get metadata from blob %q, skipping: %v", *blob.Name, err)
				continue
			}
			if metadata.FileMetadata == nil {
				plog.Infof("No file name metadata for %q, skipping.", *blob.Name)
				continue
			}
			if metadata.FileMetadata.FileName != specFileName {
				plog.Infof("Blob's file name %q doesn't match %q, skipping.", metadata.FileMetadata.FileName, specFileName)
				continue
			}
			// Get the last modified date and only delete obsolete blobs
			duration := now.Sub(*blob.Properties.LastModified)
			daysOld := int(duration.Hours() / 24)
			if daysOld < days {
				plog.Infof("Valid blob: %q: %d days old, skipping.", *blob.Name, daysOld)
				continue
			}
			plog.Infof("Obsolete blob %q: %d days old", *blob.Name, daysOld)
			if !pruneDryRun {
				plog.Infof("Deleting blob %q in container %q", *blob.Name, containerName)
				err = azure.DeleteBlob(client, containerName, *blob.Name)
				if err != nil {
					plog.Warningf("Error deleting blob (%s): %v", *blob.Name, err)
				}
			}
		}
	}
}

type deleteStats struct {
	total        int
	kept         int
	skipped      int
	recentlyUsed int
	softDeleted  int
	deleted      int
}

func pruneAWS(ctx context.Context, spec *channelSpec) {
	if spec.AWS.Image == "" || awsCredentialsFile == "" {
		plog.Notice("AWS image pruning disabled.")
		return
	}
	stats := deleteStats{}

	// Iterate over all partitions and regions in the given channel and prune
	// images in each of them.
	for _, part := range spec.AWS.Partitions {
		for _, region := range part.Regions {
			plog := capnslog.NewPackageLogger("github.com/flatcar/mantle", fmt.Sprintf("prune:%s", region))
			if pruneDryRun {
				plog.Printf("Checking for images in %v...", part.Name)
			} else {
				plog.Printf("Pruning images in %v...", part.Name)
			}

			api, err := aws.New(&aws.Options{
				CredentialsFile: awsCredentialsFile,
				Profile:         part.Profile,
				Region:          region,
			})
			if err != nil {
				plog.Fatalf("Creating client for %v %v: %v", part.Name, region, err)
			}

			images, err := api.GetImagesByTag("Channel", specChannel)
			if err != nil {
				plog.Fatalf("Couldn't list images in channel %q: %v", specChannel, err)
			}
			stats.total += len(images)

			plog.Infof("Got %d images with channel %q", len(images), specChannel)

			// sort images by creation date
			sort.Slice(images, func(i, j int) bool {
				datei, _ := time.Parse(time.RFC3339Nano, *images[i].CreationDate)
				datej, _ := time.Parse(time.RFC3339Nano, *images[j].CreationDate)
				return datei.Before(datej)
			})
			if len(images) <= keepLast {
				plog.Infof("Not enough images to prune, keeping %d", len(images))
				stats.kept += len(images)
				continue
			}
			for _, image := range images[len(images)-keepLast:] {
				plog.Infof("Keeping image %q", *image.Name)
			}
			stats.kept += keepLast
			images = images[:len(images)-keepLast]

			now := time.Now()
			for _, image := range images {
				creationDate, err := time.Parse(time.RFC3339Nano, *image.CreationDate)
				if err != nil {
					plog.Warningf("Error converting creation date (%v): %v", *image.CreationDate, err)
				}
				duration := now.Sub(creationDate)
				daysOld := int(duration.Hours() / 24)
				if daysOld < days {
					plog.Infof("Valid image %q: %d days old, skipping", *image.Name, daysOld)
					stats.skipped += 1
					continue
				}
				if checkLastLaunched {
					lastLaunched, err := api.GetImageLastLaunchedTime(*image.ImageId)
					if err != nil {
						plog.Warningf("Error converting last launched date (%v): %v", *image.ImageId, err)
						continue
					}
					duration := now.Sub(lastLaunched)
					daysOld := int(duration.Hours() / 24)
					if daysOld < daysLastLaunched {
						plog.Infof("Image %q: recently used %d days ago (%v), skipping", *image.Name, daysOld, lastLaunched)
						stats.recentlyUsed += 1
						continue
					}
				}
				plog.Infof("Obsolete image %q/%q: %d days old", *image.Name, *image.ImageId, daysOld)
				if !pruneDryRun {
					// Construct the s3ObjectPath in the same manner it's constructed for upload
					arch := *image.Architecture
					if arch == "x86_64" {
						arch = "amd64"
					}
					board := fmt.Sprintf("%s-usr", arch)
					var version string
					var softDeleteDate string
					for _, t := range image.Tags {
						if *t.Key == "Version" {
							version = *t.Value
						}
						if *t.Key == "SoftDeleteDate" {
							softDeleteDate = *t.Value
						}
					}
					if softDeleteDate == "" && daysSoftDeleted > 0 {
						softDeleteDate = now.Format(time.RFC3339)
						// remove LaunchPermission
						_, err = api.RemoveLaunchPermission(*image.ImageId)
						if err != nil {
							plog.Fatalf("Error removing launch permission from %v: %v", *image.Name, err)
						}
						// add tag
						err = api.CreateTags([]string{*image.ImageId}, map[string]string{"SoftDeleteDate": softDeleteDate})
						if err != nil {
							plog.Fatalf("Error adding tag to %v: %v", *image.Name, err)
						}
						plog.Infof("Image %v has been soft-deleted", *image.Name)
						stats.softDeleted += 1
						continue
					} else if daysSoftDeleted > 0 {
						// check if the image is still soft-deleted
						softDeleteDateTs, err := time.Parse(time.RFC3339, softDeleteDate)
						if err != nil {
							plog.Fatalf("Error converting soft-delete date (%v): %v", softDeleteDateTs, err)
						}
						duration := now.Sub(softDeleteDateTs)
						daysOld := int(duration.Hours() / 24)
						if daysOld < daysSoftDeleted {
							plog.Infof("Image %v soft-deleted %d days ago, skipping", *image.Name, daysOld)
							stats.softDeleted += 1
							continue
						}
					}

					imageFileName := strings.TrimSuffix(spec.AWS.Image, filepath.Ext(spec.AWS.Image))
					s3ObjectPath := fmt.Sprintf("%s/%s/%s", board, version, imageFileName)

					// Remove -hvm from the name, as the snapshots don't include that.
					imageName := strings.TrimSuffix(*image.Name, "-hvm")

					s3object := aws.BucketObject{
						Region: part.BucketRegion,
						Bucket: part.Bucket,
						Path:   s3ObjectPath,
					}
					err := api.RemoveImage(imageName, imageName, s3object, nil)
					if err != nil {
						plog.Fatalf("couldn't prune image %v: %v", *image.Name, err)
					}
					stats.deleted += 1
				}
			}
		}
	}
	plog.Noticef("Pruning complete: %+v", stats)
}
