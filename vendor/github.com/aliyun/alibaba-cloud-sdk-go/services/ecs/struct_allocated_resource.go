package ecs

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Code generated by Alibaba Cloud SDK Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

// AllocatedResource is a nested struct in ecs response
type AllocatedResource struct {
	AvailableAmount           int                       `json:"AvailableAmount" xml:"AvailableAmount"`
	TotalAmount               int                       `json:"TotalAmount" xml:"TotalAmount"`
	UsedAmount                int                       `json:"UsedAmount" xml:"UsedAmount"`
	InstanceType              string                    `json:"InstanceType" xml:"InstanceType"`
	ZoneId                    string                    `json:"zoneId" xml:"zoneId"`
	CapacityReservationUsages CapacityReservationUsages `json:"CapacityReservationUsages" xml:"CapacityReservationUsages"`
	ElasticityAssuranceUsages ElasticityAssuranceUsages `json:"ElasticityAssuranceUsages" xml:"ElasticityAssuranceUsages"`
}
