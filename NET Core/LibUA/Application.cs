using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LibUA.Core;

namespace LibUA
{
	namespace Server
	{
		public class Application
		{
			protected struct ServerMonitorKey : IEquatable<ServerMonitorKey>
			{
				public ServerMonitorKey(NodeId nodeId, NodeAttribute attribute)
				{
					this.NodeId = nodeId;
					this.Attribute = attribute;
				}

				public ServerMonitorKey(ReadValueId itemToMonitor)
					: this(itemToMonitor.NodeId, itemToMonitor.AttributeId)
				{
				}

				public NodeId NodeId;

				public NodeAttribute Attribute;

				public override int GetHashCode()
				{
					return (int)(NodeId.GetHashCode() ^ (int)Attribute);
				}

				public override bool Equals(object obj)
				{
					if (obj is ServerMonitorKey)
					{
						return NodeId == ((ServerMonitorKey)obj).NodeId &&
							Attribute == ((ServerMonitorKey)obj).Attribute;
					}

					return false;
				}

				public bool Equals(ServerMonitorKey other)
				{
					return NodeId.Equals(other.NodeId) && Attribute == other.Attribute;
				}
			}

			public struct SessionCreationInfo
			{
				public EndPoint Endpoint;
			}

			protected ConcurrentDictionary<NodeId, Node> AddressSpaceTable;

			HashSet<NodeId> internalAddressSpaceNodes;
			Dictionary<NodeId, object> internalAddressSpaceValues;

			ReaderWriterLockSlim monitorMapRW;
			Dictionary<ServerMonitorKey, List<MonitoredItem>> monitorMap;

			public virtual X509Certificate2 ApplicationCertificate
			{
				get { return null; }
			}

			public virtual RSACryptoServiceProvider ApplicationPrivateKey
			{
				get { return null; }
			}

			public Application()
			{
				AddressSpaceTable = new ConcurrentDictionary<NodeId, Node>();

				SetupDefaultAddressSpace();

				// Missing in the auto-generated UA specification
				// BaseDataType organizes DataTypesFolder
				AddressSpaceTable[new NodeId(UAConst.BaseDataType)].References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), new NodeId(UAConst.DataTypesFolder), false));

				SetupInternalAddressSpace();

				monitorMapRW = new ReaderWriterLockSlim();
				monitorMap = new Dictionary<ServerMonitorKey, List<MonitoredItem>>();
			}

			public virtual bool MonitorAdd(object session, MonitoredItem mi)
			{
				Node node;
				if (!AddressSpaceTable.TryGetValue(mi.ItemToMonitor.NodeId, out node) ||
					!SessionHasPermissionToRead(session, mi.ItemToMonitor.NodeId))
				{
					return false;
				}

				var key = new ServerMonitorKey(mi.ItemToMonitor);

				try
				{
					monitorMapRW.EnterWriteLock();

					List<MonitoredItem> mis = null;
					if (monitorMap.TryGetValue(key, out mis))
					{
						mis.Add(mi);
					}
					else
					{
						mis = new List<MonitoredItem>();
						mis.Add(mi);
						monitorMap.Add(key, mis);
					}
				}
				finally
				{
					monitorMapRW.ExitWriteLock();
				}

				return true;
			}

			public virtual void MonitorRemove(object session, MonitoredItem mi)
			{
				var key = new ServerMonitorKey(mi.ItemToMonitor);
				try
				{
					monitorMapRW.EnterWriteLock();
					List<MonitoredItem> mis = null;
					if (monitorMap.TryGetValue(key, out mis))
					{
						mis.Remove(mi);
					}
				}
				finally
				{
					monitorMapRW.ExitWriteLock();
				}
			}

			public virtual void MonitorNotifyDataChange(NodeId id, DataValue dv)
			{
				var key = new ServerMonitorKey(id, NodeAttribute.Value);
				//Console.WriteLine("{0} {1}", id.ToString(), dv.Value.ToString());

				try
				{
					monitorMapRW.EnterReadLock();
					List<MonitoredItem> mis = null;
					if (monitorMap.TryGetValue(key, out mis))
					{
						for (int i = 0; i < mis.Count; i++)
						{
							if (mis[i].QueueData.Count >= mis[i].QueueSize)
							{
								mis[i].QueueOverflowed = true;
							}
							else
							{
								mis[i].QueueData.Enqueue(dv);
							}

							if (mis[i].ParentSubscription.ChangeNotification == Subscription.ChangeNotificationType.None)
							{
								mis[i].ParentSubscription.ChangeNotification = Subscription.ChangeNotificationType.AtPublish;
							}
						}
					}
				}
				finally
				{
					monitorMapRW.ExitReadLock();
				}
			}

			public virtual void MonitorNotifyEvent(NodeId id, EventNotification ev)
			{
				var key = new ServerMonitorKey(id, NodeAttribute.EventNotifier);
				//Console.WriteLine("{0} {1}", id.ToString(), dv.Value.ToString());

				try
				{
					monitorMapRW.EnterReadLock();
					List<MonitoredItem> mis = null;
					if (monitorMap.TryGetValue(key, out mis))
					{
						for (int i = 0; i < mis.Count; i++)
						{
							if (mis[i].QueueEvent.Count >= mis[i].QueueSize)
							{
								mis[i].QueueOverflowed = true;
							}
							else
							{
								mis[i].QueueEvent.Enqueue(ev);
							}

							if (mis[i].ParentSubscription.ChangeNotification == Subscription.ChangeNotificationType.None)
							{
								mis[i].ParentSubscription.ChangeNotification = Subscription.ChangeNotificationType.AtPublish;
							}
						}
					}
				}
				finally
				{
					monitorMapRW.ExitReadLock();
				}
			}

			public virtual object SessionCreate(SessionCreationInfo sessionInfo)
			{
				return null;
			}

			public virtual bool SessionValidateClientApplication(object session, ApplicationDescription clientApplicationDescription, byte[] clientCertificate, string sessionName)
			{
				return true;
			}

			public virtual bool SessionValidateClientUser(object session, object userIdentityToken)
			{
				return true;
			}

			public virtual bool SessionActivateClient(object session, SecurityPolicy securityPolicy, MessageSecurityMode messageSecurityMode, X509Certificate2 remoteCertificate)
			{
				return true;
			}

			public virtual void SessionRelease(object session)
			{
			}

			public virtual Core.ApplicationDescription GetApplicationDescription(string endpointUrlHint)
			{
				return null;
			}

			public virtual IList<Core.EndpointDescription> GetEndpointDescriptions(string endpointUrlHint)
			{
				return new List<Core.EndpointDescription>();
			}

			protected virtual DataValue HandleReadRequestInternal(NodeId id)
			{
				object value;
				if (internalAddressSpaceValues.TryGetValue(id, out value))
				{
					return new DataValue(value, StatusCode.Good);
				}

				return new DataValue(null, StatusCode.Good);
			}

			void SetupInternalAddressSpace()
			{
				internalAddressSpaceNodes = new HashSet<NodeId>();
				foreach (var key in AddressSpaceTable.Keys) { internalAddressSpaceNodes.Add(key); }

				internalAddressSpaceValues = new Dictionary<NodeId, object>()
				{
					{ new NodeId(UAConst.Server_ServerArray), new string[0] },
					{ new NodeId(UAConst.Server_NamespaceArray), new string[]
						{
							"http://opcfoundation.org/UA/",
							"http://quantensystems.com/uaSDK2",
							"http://quantensystems.com/DemoServer"
						}
					},
					{ new NodeId(UAConst.Server_ServerStatus_State), (Int32)ServerState.Running },

					{ new NodeId(UAConst.OperationLimitsType_MaxNodesPerRead), 100 },
					{ new NodeId(UAConst.OperationLimitsType_MaxNodesPerWrite), 100 },
					{ new NodeId(UAConst.OperationLimitsType_MaxNodesPerMethodCall), 100 },
					{ new NodeId(UAConst.OperationLimitsType_MaxNodesPerBrowse), 100 },
					{ new NodeId(UAConst.OperationLimitsType_MaxNodesPerRegisterNodes), 100 },
					{ new NodeId(UAConst.OperationLimitsType_MaxNodesPerTranslateBrowsePathsToNodeIds), 100 },
					{ new NodeId(UAConst.OperationLimitsType_MaxNodesPerNodeManagement), 100 },
					{ new NodeId(UAConst.OperationLimitsType_MaxMonitoredItemsPerCall), 100 },
					{ new NodeId(UAConst.OperationLimitsType_MaxNodesPerHistoryReadData), 100 },
					{ new NodeId(UAConst.OperationLimitsType_MaxNodesPerHistoryUpdateData), 100 },
					{ new NodeId(UAConst.OperationLimitsType_MaxNodesPerHistoryReadEvents), 100 },
					{ new NodeId(UAConst.OperationLimitsType_MaxNodesPerHistoryUpdateEvents), 100 },

					{ new NodeId(UAConst.Server_ServerStatus_StartTime), 0 },
					{ new NodeId(UAConst.Server_ServerStatus_CurrentTime), 0 },
					{ new NodeId(UAConst.Server_ServerStatus_SecondsTillShutdown), 0 },
					{ new NodeId(UAConst.Server_ServerStatus_BuildInfo_ProductUri), "product" },
					{ new NodeId(UAConst.Server_ServerStatus_BuildInfo_ManufacturerName), "manufacturer" },
					{ new NodeId(UAConst.Server_ServerStatus_BuildInfo_ProductName), "product" },
					{ new NodeId(UAConst.Server_ServerStatus_BuildInfo_SoftwareVersion), 1.0 },
					{ new NodeId(UAConst.Server_ServerStatus_BuildInfo_BuildNumber), 1.0 },
					{ new NodeId(UAConst.Server_ServerStatus_BuildInfo_BuildDate), 0 }
				};
			}

			public bool IsSubtypeOrEqual(NodeId target, NodeId parent)
			{
				if (target.Equals(parent)) { return true; }
				if (parent.EqualsNumeric(0, 0)) { return true; }

				Node node;
				if (!AddressSpaceTable.TryGetValue(parent, out node))
				{
					return false;
				}

				for (int i = 0; i < node.References.Count; i++)
				{
					var r = node.References[i];
					if (r.IsInverse) { continue; }

					if (!r.ReferenceType.EqualsNumeric(0, (uint)UAConst.HasSubtype))
					{
						continue;
					}

					if (IsSubtypeOrEqual(target, r.Target))
					{
						return true;
					}
				}

				return false;
			}

			public virtual StatusCode HandleTranslateBrowsePathRequest(object session, BrowsePath path, List<BrowsePathTarget> res)
			{
				Node node;
				if (!AddressSpaceTable.TryGetValue(path.StartingNode, out node) ||
					!SessionHasPermissionToRead(session, path.StartingNode))
				{
					return StatusCode.BadNodeIdUnknown;
				}

				for (int i = 0; i < path.RelativePath.Length; i++)
				{
					var rp = path.RelativePath[i];
					ReferenceNode nref = null;
					for (int j = 0; j < node.References.Count; j++)
					{
						var tref = node.References[j];
						if (rp.IsInverse != tref.IsInverse)
						{
							continue;
						}

						if (!rp.IncludeSubtypes && !tref.ReferenceType.Equals(rp.ReferenceTypeId))
						{
							continue;
						}

						if (rp.IncludeSubtypes && !IsSubtypeOrEqual(tref.ReferenceType, rp.ReferenceTypeId))
						{
							continue;
						}

						Node target;
						if (!AddressSpaceTable.TryGetValue(tref.Target, out target) ||
							!SessionHasPermissionToRead(session, tref.Target))
						{
							continue;
						}

						if (target.BrowseName.Equals(rp.TargetName))
						{
							nref = node.References[j];
							node = target;
							break;
						}
					}

					if (nref == null || node == null)
					{
						res.Add(new BrowsePathTarget() { Target = node.Id, RemainingPathIndex = (uint)i });
						return StatusCode.BadNoMatch;
					}
				}

				res.Add(new BrowsePathTarget() { Target = node.Id, RemainingPathIndex = (uint)path.RelativePath.Length });
				return StatusCode.Good;
			}

			public virtual StatusCode HandleBrowseRequest(object session, BrowseDescription browseDesc, List<ReferenceDescription> results, int maxResults, ContinuationPointBrowse cont)
			{
				Node node;
				if (!AddressSpaceTable.TryGetValue(browseDesc.Id, out node) ||
					!SessionHasPermissionToRead(session, browseDesc.Id))
				{
					return StatusCode.BadNodeIdUnknown;
				}

				bool referenceTypeSpecified = !browseDesc.ReferenceType.EqualsNumeric(0, 0);

				results.Clear();
				for (int i = cont.IsValid ? cont.Offset : 0; i < node.References.Count; i++)
				{
					var r = node.References[i];

					if (browseDesc.Direction == BrowseDirection.Forward && r.IsInverse ||
						browseDesc.Direction == BrowseDirection.Inverse && !r.IsInverse)
					{
						continue;
					}

					if (referenceTypeSpecified && !browseDesc.IncludeSubtypes && !r.ReferenceType.Equals(browseDesc.ReferenceType))
					{
						continue;
					}

					if (referenceTypeSpecified && browseDesc.IncludeSubtypes && !IsSubtypeOrEqual(r.ReferenceType, browseDesc.ReferenceType))
					{
						continue;
					}

					if (results.Count == maxResults)
					{
						cont.Offset = i;
						cont.IsValid = true;

						// TODO: Set continuation point
						return StatusCode.GoodMoreData;
					}

					NodeId typeDef = NodeId.Zero;
					Node targetNode = null;
					if (!AddressSpaceTable.TryGetValue(r.Target, out targetNode) ||
						!SessionHasPermissionToRead(session, r.Target))
					{
						results.Add(new ReferenceDescription(r.ReferenceType, !r.IsInverse, r.Target,
							new QualifiedName(), new LocalizedText(string.Empty), NodeClass.Unspecified, typeDef));
					}
					else
					{
						if (browseDesc.NodeClassMask > 0 && ((uint)targetNode.GetNodeClass() & browseDesc.NodeClassMask) == 0)
						{
							continue;
						}

						if (targetNode.References != null && (targetNode is NodeObject || targetNode is NodeVariable))
						{
							for (int j = 0; j < targetNode.References.Count; j++)
							{
								if (targetNode.References[j].ReferenceType.EqualsNumeric(0, (uint)UAConst.HasTypeDefinition))
								{
									typeDef = targetNode.References[j].Target;
								}
							}
						}
					}

					results.Add(new ReferenceDescription(r.ReferenceType, !r.IsInverse, r.Target, targetNode.BrowseName, targetNode.DisplayName, targetNode.GetNodeClass(), typeDef));
				}

				//Console.WriteLine("Browse {0} {1} -> {2}",
				//	browseDesc.Id.ToString(), node.DisplayName.ToString(),
				//	results.Count == 0 ? "(no results)" :
				//	string.Join(", ", results.Select(r => r.DisplayName.ToString())));

				cont.IsValid = false;
				return StatusCode.Good;
			}

			public virtual UInt32[] HandleWriteRequest(object session, WriteValue[] writeValues)
			{
				var respStatus = new UInt32[writeValues.Length];
				for (int i = 0; i < writeValues.Length; i++)
				{
					respStatus[i] = (UInt32)StatusCode.BadNotWritable;
				}

				return respStatus;
			}

			public virtual UInt32 HandleHistoryReadRequest(object session, object readDetails, HistoryReadValueId id, ContinuationPointHistory continuationPoint, List<DataValue> results, ref int? offsetContinueFit)
			{
				return (UInt32)StatusCode.BadNotImplemented;
			}

			public virtual UInt32[] HandleHistoryUpdateRequest(object session, HistoryUpdateData[] updates)
			{
				UInt32[] resps = new UInt32[updates.Length];
				for (int i = 0; i < updates.Length; i++)
				{
					resps[i] = (UInt32)StatusCode.BadNotImplemented;
				}

				return resps;
			}

			public virtual UInt32 HandleHistoryEventReadRequest(object session, object readDetails, HistoryReadValueId id, ContinuationPointHistory continuationPoint, List<object[]> results)
			{
				return (UInt32)StatusCode.BadNotImplemented;
			}

			public virtual DataValue[] HandleReadRequest(object session, ReadValueId[] readValueIds)
			{
				var res = new DataValue[readValueIds.Length];

				for (int i = 0; i < readValueIds.Length; i++)
				{
					Node node = null;
					if (!AddressSpaceTable.TryGetValue(readValueIds[i].NodeId, out node) ||
						!SessionHasPermissionToRead(session, readValueIds[i].NodeId))
					{
						Console.WriteLine($"Read node {readValueIds[i].NodeId} unknown {readValueIds[i].AttributeId}");
						res[i] = new DataValue(null, StatusCode.BadNodeIdUnknown);
						continue;
					}

					if (readValueIds[i].AttributeId == NodeAttribute.Value)
					{
						res[i] = HandleReadRequestInternal(readValueIds[i].NodeId);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.NodeId)
					{
						res[i] = new DataValue(node.Id, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.NodeClass)
					{
						NodeClass nodeClass = node.GetNodeClass();
						res[i] = new DataValue((Int32)nodeClass, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.BrowseName)
					{
						res[i] = new DataValue(node.BrowseName, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.DisplayName)
					{
						res[i] = new DataValue(node.DisplayName, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.Description)
					{
						res[i] = new DataValue(node.Description, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.WriteMask)
					{
						res[i] = new DataValue(node.WriteMask, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.UserWriteMask)
					{
						res[i] = new DataValue(node.UserWriteMask, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.AccessRestrictions)
					{
						res[i] = new DataValue((UInt16)0, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.IsAbstract && node is NodeReferenceType)
					{
						res[i] = new DataValue((node as NodeReferenceType).IsAbstract, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.Symmetric && node is NodeReferenceType)
					{
						res[i] = new DataValue((node as NodeReferenceType).IsSymmetric, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.InverseName && node is NodeReferenceType)
					{
						res[i] = new DataValue((node as NodeReferenceType).InverseName, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.ContainsNoLoops && node is NodeView)
					{
						res[i] = new DataValue((node as NodeView).ContainsNoLoops, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.EventNotifier && node is NodeView)
					{
						res[i] = new DataValue((node as NodeView).EventNotifier, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.EventNotifier && node is NodeObject)
					{
						res[i] = new DataValue((node as NodeObject).EventNotifier, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.DataType && node is NodeVariable)
					{
						res[i] = new DataValue((node as NodeVariable).DataType ?? new NodeId(UAConst.BaseDataType), StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.DataType && node is NodeVariableType)
					{
						res[i] = new DataValue((node as NodeVariableType).DataType ?? new NodeId(UAConst.BaseDataType), StatusCode.Good);
					}
					else if ((readValueIds[i].AttributeId == NodeAttribute.AccessLevel ||
						readValueIds[i].AttributeId == NodeAttribute.AccessLevelEx) && node is NodeVariable)
					{
						res[i] = new DataValue((byte)(node as NodeVariable).AccessLevel, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.UserAccessLevel && node is NodeVariable)
					{
						res[i] = new DataValue((byte)(node as NodeVariable).UserAccessLevel, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.Historizing && node is NodeVariable)
					{
						res[i] = new DataValue((node as NodeVariable).IsHistorizing, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.MinimumSamplingInterval && node is NodeVariable)
					{
						res[i] = new DataValue((node as NodeVariable).MinimumResamplingInterval, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.Executable && node is NodeMethod)
					{
						res[i] = new DataValue((node as NodeMethod).IsExecutable, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.UserExecutable && node is NodeMethod)
					{
						res[i] = new DataValue((node as NodeMethod).IsUserExecutable, StatusCode.Good);
					}
					else if (readValueIds[i].AttributeId == NodeAttribute.ValueRank && node is NodeVariable)
					{
						res[i] = new DataValue((Int32)(node as NodeVariable).ValueRank, StatusCode.Good);
					}
					else
					{
						res[i] = new DataValue(null, StatusCode.BadAttributeIdInvalid);
					}

					Console.WriteLine($"Read node {readValueIds[i].NodeId} {node.DisplayName.Text} {readValueIds[i].AttributeId} => {res[i].Value ?? "### NULL"}");
				}

				return res;
			}

			protected bool SessionHasPermissionToRead(object session, NodeId nodeId)
			{
				return true;
			}

			private void AddDefaultAddressSpaceNodeVariable(uint id, string qualifiedName, string displayName, string description,
				UInt32 writeMask, UInt32 userWriteMask, Core.AccessLevel accessLevel, Core.AccessLevel userAccessLevel, double minimumResamplingInterval, bool isHistorizing, uint dataType,
				(uint referenceType, uint target, bool isInverse)[] references)
			{
				var node = new NodeVariable(new NodeId(id), new QualifiedName(qualifiedName), new LocalizedText(displayName), new LocalizedText(description), writeMask, userWriteMask, accessLevel, userAccessLevel, minimumResamplingInterval, isHistorizing, new NodeId(dataType));

				if (references != null)
				{
					foreach (var r in references)
					{
						node.References.Add(new ReferenceNode(new NodeId(r.referenceType), new NodeId(r.target), r.isInverse));
					}
				}
				AddressSpaceTable.TryAdd(node.Id, node);
			}

			//NodeVariableType(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, bool IsAbstract)
			private void AddDefaultAddressSpaceNodeVariableType(uint id, string qualifiedName, string displayName, string description,
				UInt32 writeMask, UInt32 userWriteMask, bool isAbstract,
				(uint referenceType, uint target, bool isInverse)[] references)
			{
				var node = new NodeVariableType(new NodeId(id), new QualifiedName(qualifiedName), new LocalizedText(displayName), new LocalizedText(description), writeMask, userWriteMask, isAbstract);

				if (references != null)
				{
					foreach (var r in references)
					{
						node.References.Add(new ReferenceNode(new NodeId(r.referenceType), new NodeId(r.target), r.isInverse));
					}
				}
				AddressSpaceTable.TryAdd(node.Id, node);
			}

			//NodeDataType(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, bool IsAbstract)
			private void AddDefaultAddressSpaceNodeDataType(uint id, string qualifiedName, string displayName, string description,
				UInt32 writeMask, UInt32 userWriteMask, bool isAbstract,
				(uint referenceType, uint target, bool isInverse)[] references)
			{
				var node = new NodeDataType(new NodeId(id), new QualifiedName(qualifiedName), new LocalizedText(displayName), new LocalizedText(description), writeMask, userWriteMask, isAbstract);

				if (references != null)
				{
					foreach (var r in references)
					{
						node.References.Add(new ReferenceNode(new NodeId(r.referenceType), new NodeId(r.target), r.isInverse));
					}
				}
				AddressSpaceTable.TryAdd(node.Id, node);
			}

			//NodeMethod(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, bool IsExecutable, bool IsUserExecutable)
			private void AddDefaultAddressSpaceNodeMethod(uint id, string qualifiedName, string displayName, string description,
				UInt32 writeMask, UInt32 userWriteMask, bool isExecutable, bool isUserExecutable,
				(uint referenceType, uint target, bool isInverse)[] references)
			{
				var node = new NodeMethod(new NodeId(id), new QualifiedName(qualifiedName), new LocalizedText(displayName), new LocalizedText(description), writeMask, userWriteMask, isExecutable, isUserExecutable);

				if (references != null)
				{
					foreach (var r in references)
					{
						node.References.Add(new ReferenceNode(new NodeId(r.referenceType), new NodeId(r.target), r.isInverse));
					}
				}
				AddressSpaceTable.TryAdd(node.Id, node);
			}

			//NodeObject(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, byte EventNotifier)
			private void AddDefaultAddressSpaceNodeObject(uint id, string qualifiedName, string displayName, string description,
				UInt32 writeMask, UInt32 userWriteMask, byte eventNotifier,
				(uint referenceType, uint target, bool isInverse)[] references)
			{
				var node = new NodeObject(new NodeId(id), new QualifiedName(qualifiedName), new LocalizedText(displayName), new LocalizedText(description), writeMask, userWriteMask, eventNotifier);

				if (references != null)
				{
					foreach (var r in references)
					{
						node.References.Add(new ReferenceNode(new NodeId(r.referenceType), new NodeId(r.target), r.isInverse));
					}
				}
				AddressSpaceTable.TryAdd(node.Id, node);
			}


			//NodeObjectType(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, bool IsAbstract)
			private void AddDefaultAddressSpaceNodeObjectType(uint id, string qualifiedName, string displayName, string description,
				UInt32 writeMask, UInt32 userWriteMask, bool isAbstract,
				(uint referenceType, uint target, bool isInverse)[] references)
			{
				var node = new NodeObjectType(new NodeId(id), new QualifiedName(qualifiedName), new LocalizedText(displayName), new LocalizedText(description), writeMask, userWriteMask, isAbstract);

				if (references != null)
				{
					foreach (var r in references)
					{
						node.References.Add(new ReferenceNode(new NodeId(r.referenceType), new NodeId(r.target), r.isInverse));
					}
				}
				AddressSpaceTable.TryAdd(node.Id, node);
			}

			//NodeReferenceType(NodeId Id, QualifiedName BrowseName, LocalizedText DisplayName, LocalizedText Description, UInt32 WriteMask, UInt32 UserWriteMask, bool IsAbstract, bool IsSymmetric, LocalizedText InverseName)
			private void AddDefaultAddressSpaceNodeReferenceType(uint id, string qualifiedName, string displayName, string description,
				UInt32 writeMask, UInt32 userWriteMask, bool isAbstract, bool isSymmetric, string inverseName,
				(uint referenceType, uint target, bool isInverse)[] references)
			{
				var node = new NodeReferenceType(new NodeId(id), new QualifiedName(qualifiedName), new LocalizedText(displayName), new LocalizedText(description), writeMask, userWriteMask, isAbstract, isSymmetric, new LocalizedText(inverseName));

				if (references != null)
				{
					foreach (var r in references)
					{
						node.References.Add(new ReferenceNode(new NodeId(r.referenceType), new NodeId(r.target), r.isInverse));
					}
				}
				AddressSpaceTable.TryAdd(node.Id, node);
			}

			private void Part1()
			{
				// References, i=31, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 -> NonHierarchicalReferences/32
				//	HasSubtype/45 -> HierarchicalReferences/33
				AddDefaultAddressSpaceNodeReferenceType(31, "References", "References", "The abstract base type for all references.", 0, 0, true, false, "References", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  false),
					(45,  33,  false),
				});

				// NonHierarchicalReferences, i=32, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- References/31
				//	HasSubtype/45 -> HasModellingRule/37
				//	HasSubtype/45 -> HasEncoding/38
				//	HasSubtype/45 -> HasDescription/39
				//	HasSubtype/45 -> HasTypeDefinition/40
				//	HasSubtype/45 -> GeneratesEvent/41
				//	HasSubtype/45 -> AlwaysGeneratesEvent/3065
				//	HasSubtype/45 -> FromState/51
				//	HasSubtype/45 -> ToState/52
				//	HasSubtype/45 -> HasCause/53
				//	HasSubtype/45 -> HasEffect/54
				//	HasSubtype/45 -> HasSubStateMachine/117
				//	HasSubtype/45 -> HasTrueSubState/9004
				//	HasSubtype/45 -> HasFalseSubState/9005
				//	HasSubtype/45 -> HasCondition/9006
				AddDefaultAddressSpaceNodeReferenceType(32, "NonHierarchicalReferences", "NonHierarchicalReferences", "The abstract base type for all non-hierarchical references.", 0, 0, true, false, "NonHierarchicalReferences", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  31,  true),
					(45,  37,  false),
					(45,  38,  false),
					(45,  39,  false),
					(45,  40,  false),
					(45,  41,  false),
					(45,  3065,  false),
					(45,  51,  false),
					(45,  52,  false),
					(45,  53,  false),
					(45,  54,  false),
					(45,  117,  false),
					(45,  9004,  false),
					(45,  9005,  false),
					(45,  9006,  false),
				});

				// HierarchicalReferences, i=33, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- References/31
				//	HasSubtype/45 -> HasChild/34
				//	HasSubtype/45 -> Organizes/35
				//	HasSubtype/45 -> HasEventSource/36
				AddDefaultAddressSpaceNodeReferenceType(33, "HierarchicalReferences", "HierarchicalReferences", "The abstract base type for all hierarchical references.", 0, 0, true, false, "HierarchicalReferences", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  31,  true),
					(45,  34,  false),
					(45,  35,  false),
					(45,  36,  false),
				});

				// HasChild, i=34, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- HierarchicalReferences/33
				//	HasSubtype/45 -> Aggregates/44
				//	HasSubtype/45 -> HasSubtype/45
				AddDefaultAddressSpaceNodeReferenceType(34, "HasChild", "HasChild", "The abstract base type for all non-looping hierarchical references.", 0, 0, false, false, "ChildOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  33,  true),
					(45,  44,  false),
					(45,  45,  false),
				});

				// Organizes, i=35, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- HierarchicalReferences/33
				AddDefaultAddressSpaceNodeReferenceType(35, "Organizes", "Organizes", "The type for hierarchical references that are used to organize nodes.", 0, 0, false, false, "OrganizedBy", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  33,  true),
				});

				// HasEventSource, i=36, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- HierarchicalReferences/33
				//	HasSubtype/45 -> HasNotifier/48
				AddDefaultAddressSpaceNodeReferenceType(36, "HasEventSource", "HasEventSource", "The type for non-looping hierarchical references that are used to organize event sources.", 0, 0, false, false, "EventSourceOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  33,  true),
					(45,  48,  false),
				});

				// HasModellingRule, i=37, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- NonHierarchicalReferences/32
				AddDefaultAddressSpaceNodeReferenceType(37, "HasModellingRule", "HasModellingRule", "The type for references from instance declarations to modelling rule nodes.", 0, 0, false, false, "ModellingRuleOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  true),
				});

				// HasEncoding, i=38, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- NonHierarchicalReferences/32
				AddDefaultAddressSpaceNodeReferenceType(38, "HasEncoding", "HasEncoding", "The type for references from data type nodes to to data type encoding nodes.", 0, 0, false, false, "EncodingOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  true),
				});

				// HasDescription, i=39, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- NonHierarchicalReferences/32
				AddDefaultAddressSpaceNodeReferenceType(39, "HasDescription", "HasDescription", "The type for references from data type encoding nodes to data type description nodes.", 0, 0, false, false, "DescriptionOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  true),
				});

				// HasTypeDefinition, i=40, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- NonHierarchicalReferences/32
				AddDefaultAddressSpaceNodeReferenceType(40, "HasTypeDefinition", "HasTypeDefinition", "The type for references from a instance node its type defintion node.", 0, 0, false, false, "TypeDefinitionOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  true),
				});

				// GeneratesEvent, i=41, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- NonHierarchicalReferences/32
				AddDefaultAddressSpaceNodeReferenceType(41, "GeneratesEvent", "GeneratesEvent", "The type for references from a node to an event type that is raised by node.", 0, 0, false, false, "GeneratesEvent", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  true),
				});

				// AlwaysGeneratesEvent, i=3065, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- NonHierarchicalReferences/32
				AddDefaultAddressSpaceNodeReferenceType(3065, "AlwaysGeneratesEvent", "AlwaysGeneratesEvent", "The type for references from a node to an event type that is always raised by node.", 0, 0, false, false, "AlwaysGeneratesEvent", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  true),
				});

				// Aggregates, i=44, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- HasChild/34
				//	HasSubtype/45 -> HasProperty/46
				//	HasSubtype/45 -> HasComponent/47
				//	HasSubtype/45 -> HasHistoricalConfiguration/56
				AddDefaultAddressSpaceNodeReferenceType(44, "Aggregates", "Aggregates", "The type for non-looping hierarchical references that are used to aggregate nodes into complex types.", 0, 0, false, false, "AggregatedBy", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  34,  true),
					(45,  46,  false),
					(45,  47,  false),
					(45,  56,  false),
				});

				// HasSubtype, i=45, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- HasChild/34
				AddDefaultAddressSpaceNodeReferenceType(45, "HasSubtype", "HasSubtype", "The type for non-looping hierarchical references that are used to define sub types.", 0, 0, false, false, "HasSupertype", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  34,  true),
				});

				// HasProperty, i=46, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- Aggregates/44
				AddDefaultAddressSpaceNodeReferenceType(46, "HasProperty", "HasProperty", "The type for non-looping hierarchical reference from a node to its property.", 0, 0, false, false, "PropertyOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  44,  true),
				});

				// HasComponent, i=47, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- Aggregates/44
				//	HasSubtype/45 -> HasOrderedComponent/49
				AddDefaultAddressSpaceNodeReferenceType(47, "HasComponent", "HasComponent", "The type for non-looping hierarchical reference from a node to its component.", 0, 0, false, false, "ComponentOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  44,  true),
					(45,  49,  false),
				});

				// HasNotifier, i=48, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- HasEventSource/36
				AddDefaultAddressSpaceNodeReferenceType(48, "HasNotifier", "HasNotifier", "The type for non-looping hierarchical references that are used to indicate how events propagate from node to node.", 0, 0, false, false, "NotifierOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  36,  true),
				});

				// HasOrderedComponent, i=49, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- HasComponent/47
				AddDefaultAddressSpaceNodeReferenceType(49, "HasOrderedComponent", "HasOrderedComponent", "The type for non-looping hierarchical reference from a node to its component when the order of references matters.", 0, 0, false, false, "OrderedComponentOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  47,  true),
				});

				// FromState, i=51, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- NonHierarchicalReferences/32
				AddDefaultAddressSpaceNodeReferenceType(51, "FromState", "FromState", "The type for a reference to the state before a transition.", 0, 0, false, false, "ToTransition", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  true),
				});

				// ToState, i=52, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- NonHierarchicalReferences/32
				AddDefaultAddressSpaceNodeReferenceType(52, "ToState", "ToState", "The type for a reference to the state after a transition.", 0, 0, false, false, "FromTransition", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  true),
				});

				// HasCause, i=53, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- NonHierarchicalReferences/32
				AddDefaultAddressSpaceNodeReferenceType(53, "HasCause", "HasCause", "The type for a reference to a method that can cause a transition to occur.", 0, 0, false, false, "MayBeCausedBy", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  true),
				});

				// HasEffect, i=54, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- NonHierarchicalReferences/32
				AddDefaultAddressSpaceNodeReferenceType(54, "HasEffect", "HasEffect", "The type for a reference to an event that may be raised when a transition occurs.", 0, 0, false, false, "MayBeEffectedBy", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  true),
				});

				// HasSubStateMachine, i=117, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- NonHierarchicalReferences/32
				AddDefaultAddressSpaceNodeReferenceType(117, "HasSubStateMachine", "HasSubStateMachine", "The type for a reference to a substate for a state.", 0, 0, false, false, "SubStateMachineOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  true),
				});

				// HasHistoricalConfiguration, i=56, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- Aggregates/44
				AddDefaultAddressSpaceNodeReferenceType(56, "HasHistoricalConfiguration", "HasHistoricalConfiguration", "The type for a reference to the historical configuration for a data variable.", 0, 0, false, false, "HistoricalConfigurationOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  44,  true),
				});

				// HasTrueSubState, i=9004, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- NonHierarchicalReferences/32
				AddDefaultAddressSpaceNodeReferenceType(9004, "HasTrueSubState", "HasTrueSubState", "", 0, 0, false, false, "IsTrueSubStateOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  true),
				});

				// HasFalseSubState, i=9005, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- NonHierarchicalReferences/32
				AddDefaultAddressSpaceNodeReferenceType(9005, "HasFalseSubState", "HasFalseSubState", "", 0, 0, false, false, "IsFalseSubStateOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  true),
				});

				// HasCondition, i=9006, TypeGenerator.AddressSpaceGenerator+NodeReferenceType
				//	HasSubtype/45 <- NonHierarchicalReferences/32
				AddDefaultAddressSpaceNodeReferenceType(9006, "HasCondition", "HasCondition", "", 0, 0, false, false, "IsConditionOf", new (uint referenceType, uint target, bool isInverse)[] {
					(45,  32,  true),
				});

				// BaseDataType, i=24, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 -> Number/26
				//	HasSubtype/45 -> Enumeration/29
				//	HasSubtype/45 -> Boolean/1
				//	HasSubtype/45 -> String/12
				//	HasSubtype/45 -> DateTime/13
				//	HasSubtype/45 -> Guid/14
				//	HasSubtype/45 -> ByteString/15
				//	HasSubtype/45 -> XmlElement/16
				//	HasSubtype/45 -> NodeId/17
				//	HasSubtype/45 -> ExpandedNodeId/18
				//	HasSubtype/45 -> StatusCode/19
				//	HasSubtype/45 -> QualifiedName/20
				//	HasSubtype/45 -> LocalizedText/21
				//	HasSubtype/45 -> Structure/22
				//	HasSubtype/45 -> DataValue/23
				//	HasSubtype/45 -> DiagnosticInfo/25
				AddDefaultAddressSpaceNodeDataType(24, "BaseDataType", "BaseDataType", "Describes a value that can have any valid DataType.", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  26,  false),
					(45,  29,  false),
					(45,  1,  false),
					(45,  12,  false),
					(45,  13,  false),
					(45,  14,  false),
					(45,  15,  false),
					(45,  16,  false),
					(45,  17,  false),
					(45,  18,  false),
					(45,  19,  false),
					(45,  20,  false),
					(45,  21,  false),
					(45,  22,  false),
					(45,  23,  false),
					(45,  25,  false),
				});

				// Number, i=26, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				//	HasSubtype/45 -> Integer/27
				//	HasSubtype/45 -> Float/10
				//	HasSubtype/45 -> Double/11
				AddDefaultAddressSpaceNodeDataType(26, "Number", "Number", "Describes a value that can have any numeric DataType.", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
					(45,  27,  false),
					(45,  10,  false),
					(45,  11,  false),
				});

				// Integer, i=27, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Number/26
				//	HasSubtype/45 -> UInteger/28
				//	HasSubtype/45 -> SByte/2
				//	HasSubtype/45 -> Int16/4
				//	HasSubtype/45 -> Int32/6
				//	HasSubtype/45 -> Int64/8
				AddDefaultAddressSpaceNodeDataType(27, "Integer", "Integer", "Describes a value that can have any integer DataType.", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  26,  true),
					(45,  28,  false),
					(45,  2,  false),
					(45,  4,  false),
					(45,  6,  false),
					(45,  8,  false),
				});

				// UInteger, i=28, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Integer/27
				//	HasSubtype/45 -> Byte/3
				//	HasSubtype/45 -> UInt16/5
				//	HasSubtype/45 -> UInt32/7
				//	HasSubtype/45 -> UInt64/9
				AddDefaultAddressSpaceNodeDataType(28, "UInteger", "UInteger", "Describes a value that can have any unsigned integer DataType.", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  27,  true),
					(45,  3,  false),
					(45,  5,  false),
					(45,  7,  false),
					(45,  9,  false),
				});

				// Enumeration, i=29, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				//	HasSubtype/45 -> NamingRuleType/120
				//	HasSubtype/45 -> OpenFileMode/11939
				//	HasSubtype/45 -> IdType/256
				//	HasSubtype/45 -> NodeClass/257
				//	HasSubtype/45 -> ApplicationType/307
				//	HasSubtype/45 -> MessageSecurityMode/302
				//	HasSubtype/45 -> UserTokenType/303
				//	HasSubtype/45 -> SecurityTokenRequestType/315
				//	HasSubtype/45 -> NodeAttributesMask/348
				//	HasSubtype/45 -> AttributeWriteMask/347
				//	HasSubtype/45 -> ComplianceLevel/334
				//	HasSubtype/45 -> FilterOperator/576
				//	HasSubtype/45 -> HistoryUpdateType/11234
				//	HasSubtype/45 -> PerformUpdateType/11293
				//	HasSubtype/45 -> EnumeratedTestType/398
				//	HasSubtype/45 -> RedundancySupport/851
				//	HasSubtype/45 -> ServerState/852
				//	HasSubtype/45 -> AxisScaleEnumeration/12077
				//	HasSubtype/45 -> ExceptionDeviationFormat/890
				AddDefaultAddressSpaceNodeDataType(29, "Enumeration", "Enumeration", "Describes a value that is an enumerated DataType.", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
					(45,  120,  false),
					(45,  11939,  false),
					(45,  256,  false),
					(45,  257,  false),
					(45,  307,  false),
					(45,  302,  false),
					(45,  303,  false),
					(45,  315,  false),
					(45,  348,  false),
					(45,  347,  false),
					(45,  334,  false),
					(45,  576,  false),
					(45,  11234,  false),
					(45,  11293,  false),
					(45,  398,  false),
					(45,  851,  false),
					(45,  852,  false),
					(45,  12077,  false),
					(45,  890,  false),
				});

				// Boolean, i=1, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				AddDefaultAddressSpaceNodeDataType(1, "Boolean", "Boolean", "Describes a value that is either TRUE or FALSE.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
				});

				// SByte, i=2, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Integer/27
				AddDefaultAddressSpaceNodeDataType(2, "SByte", "SByte", "Describes a value that is an integer between -128 and 127.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  27,  true),
				});

				// Byte, i=3, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- UInteger/28
				AddDefaultAddressSpaceNodeDataType(3, "Byte", "Byte", "Describes a value that is an integer between 0 and 255.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  28,  true),
				});

				// Int16, i=4, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Integer/27
				AddDefaultAddressSpaceNodeDataType(4, "Int16", "Int16", "Describes a value that is an integer between −32,768 and 32,767.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  27,  true),
				});

				// UInt16, i=5, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- UInteger/28
				AddDefaultAddressSpaceNodeDataType(5, "UInt16", "UInt16", "Describes a value that is an integer between 0 and 65535.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  28,  true),
				});

				// Int32, i=6, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Integer/27
				AddDefaultAddressSpaceNodeDataType(6, "Int32", "Int32", "Describes a value that is an integer between −2,147,483,648  and 2,147,483,647.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  27,  true),
				});

				// UInt32, i=7, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- UInteger/28
				//	HasSubtype/45 -> IntegerId/288
				//	HasSubtype/45 -> Counter/289
				AddDefaultAddressSpaceNodeDataType(7, "UInt32", "UInt32", "Describes a value that is an integer between 0 and 4,294,967,295.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  28,  true),
					(45,  288,  false),
					(45,  289,  false),
				});

				// Int64, i=8, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Integer/27
				AddDefaultAddressSpaceNodeDataType(8, "Int64", "Int64", "Describes a value that is an integer between −9,223,372,036,854,775,808 and 9,223,372,036,854,775,807.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  27,  true),
				});

				// UInt64, i=9, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- UInteger/28
				//	HasSubtype/45 -> BitFieldMaskDataType/11737
				AddDefaultAddressSpaceNodeDataType(9, "UInt64", "UInt64", "Describes a value that is an integer between 0 and 18,446,744,073,709,551,615.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  28,  true),
					(45,  11737,  false),
				});

				// Float, i=10, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Number/26
				AddDefaultAddressSpaceNodeDataType(10, "Float", "Float", "Describes a value that is an IEEE 754-1985 single precision floating point number.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  26,  true),
				});

				// Double, i=11, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Number/26
				//	HasSubtype/45 -> Duration/290
				AddDefaultAddressSpaceNodeDataType(11, "Double", "Double", "Describes a value that is an IEEE 754-1985 double precision floating point number.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  26,  true),
					(45,  290,  false),
				});

				// String, i=12, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				//	HasSubtype/45 -> LocaleId/295
				//	HasSubtype/45 -> NumericRange/291
				//	HasSubtype/45 -> Time/292
				AddDefaultAddressSpaceNodeDataType(12, "String", "String", "Describes a value that is a sequence of printable Unicode characters.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
					(45,  295,  false),
					(45,  291,  false),
					(45,  292,  false),
				});

				// DateTime, i=13, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				//	HasSubtype/45 -> UtcTime/294
				//	HasSubtype/45 -> Date/293
				AddDefaultAddressSpaceNodeDataType(13, "DateTime", "DateTime", "Describes a value that is a Gregorian calender date and time.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
					(45,  294,  false),
					(45,  293,  false),
				});

				// Guid, i=14, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				AddDefaultAddressSpaceNodeDataType(14, "Guid", "Guid", "Describes a value that is a 128-bit globally unique identifier.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
				});

				// ByteString, i=15, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				//	HasSubtype/45 -> Image/30
				//	HasSubtype/45 -> ApplicationInstanceCertificate/311
				//	HasSubtype/45 -> ContinuationPoint/521
				AddDefaultAddressSpaceNodeDataType(15, "ByteString", "ByteString", "Describes a value that is a sequence of bytes.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
					(45,  30,  false),
					(45,  311,  false),
					(45,  521,  false),
				});

				// XmlElement, i=16, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				AddDefaultAddressSpaceNodeDataType(16, "XmlElement", "XmlElement", "Describes a value that is an XML element.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
				});

				// NodeId, i=17, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				//	HasSubtype/45 -> SessionAuthenticationToken/388
				AddDefaultAddressSpaceNodeDataType(17, "NodeId", "NodeId", "Describes a value that is an identifier for a node within a Server address space.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
					(45,  388,  false),
				});

				// ExpandedNodeId, i=18, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				AddDefaultAddressSpaceNodeDataType(18, "ExpandedNodeId", "ExpandedNodeId", "Describes a value that is an absolute identifier for a node.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
				});

				// StatusCode, i=19, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				AddDefaultAddressSpaceNodeDataType(19, "StatusCode", "StatusCode", "Describes a value that is a code representing the outcome of an operation by a Server.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
				});

				// QualifiedName, i=20, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				AddDefaultAddressSpaceNodeDataType(20, "QualifiedName", "QualifiedName", "Describes a value that is a name qualified by a namespace.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
				});

				// LocalizedText, i=21, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				AddDefaultAddressSpaceNodeDataType(21, "LocalizedText", "LocalizedText", "Describes a value that is human readable Unicode text with a locale identifier.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
				});

				// Structure, i=22, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				//	HasSubtype/45 -> Argument/296
				//	HasSubtype/45 -> EnumValueType/7594
				//	HasSubtype/45 -> TimeZoneDataType/8912
				//	HasSubtype/45 -> ApplicationDescription/308
				//	HasSubtype/45 -> UserTokenPolicy/304
				//	HasSubtype/45 -> EndpointDescription/312
				//	HasSubtype/45 -> RegisteredServer/432
				//	HasSubtype/45 -> SignedSoftwareCertificate/344
				//	HasSubtype/45 -> UserIdentityToken/316
				//	HasSubtype/45 -> AddNodesItem/376
				//	HasSubtype/45 -> AddReferencesItem/379
				//	HasSubtype/45 -> DeleteNodesItem/382
				//	HasSubtype/45 -> DeleteReferencesItem/385
				//	HasSubtype/45 -> EndpointConfiguration/331
				//	HasSubtype/45 -> SupportedProfile/335
				//	HasSubtype/45 -> SoftwareCertificate/341
				//	HasSubtype/45 -> ContentFilterElement/583
				//	HasSubtype/45 -> ContentFilter/586
				//	HasSubtype/45 -> FilterOperand/589
				//	HasSubtype/45 -> HistoryEvent/659
				//	HasSubtype/45 -> MonitoringFilter/719
				//	HasSubtype/45 -> AggregateConfiguration/948
				//	HasSubtype/45 -> HistoryEventFieldList/920
				//	HasSubtype/45 -> ScalarTestType/399
				//	HasSubtype/45 -> ArrayTestType/402
				//	HasSubtype/45 -> CompositeTestType/405
				//	HasSubtype/45 -> BuildInfo/338
				//	HasSubtype/45 -> RedundantServerDataType/853
				//	HasSubtype/45 -> EndpointUrlListDataType/11943
				//	HasSubtype/45 -> NetworkGroupDataType/11944
				//	HasSubtype/45 -> SamplingIntervalDiagnosticsDataType/856
				//	HasSubtype/45 -> ServerDiagnosticsSummaryDataType/859
				//	HasSubtype/45 -> ServerStatusDataType/862
				//	HasSubtype/45 -> SessionDiagnosticsDataType/865
				//	HasSubtype/45 -> SessionSecurityDiagnosticsDataType/868
				//	HasSubtype/45 -> ServiceCounterDataType/871
				//	HasSubtype/45 -> StatusResult/299
				//	HasSubtype/45 -> SubscriptionDiagnosticsDataType/874
				//	HasSubtype/45 -> ModelChangeStructureDataType/877
				//	HasSubtype/45 -> SemanticChangeStructureDataType/897
				//	HasSubtype/45 -> Range/884
				//	HasSubtype/45 -> EUInformation/887
				//	HasSubtype/45 -> ComplexNumberType/12171
				//	HasSubtype/45 -> DoubleComplexNumberType/12172
				//	HasSubtype/45 -> AxisInformation/12079
				//	HasSubtype/45 -> XVType/12080
				//	HasSubtype/45 -> ProgramDiagnosticDataType/894
				//	HasSubtype/45 -> Annotation/891
				AddDefaultAddressSpaceNodeDataType(22, "Structure", "Structure", "Describes a value that is any type of structure that can be described with a data encoding.", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
					(45,  296,  false),
					(45,  7594,  false),
					(45,  8912,  false),
					(45,  308,  false),
					(45,  304,  false),
					(45,  312,  false),
					(45,  432,  false),
					(45,  344,  false),
					(45,  316,  false),
					(45,  376,  false),
					(45,  379,  false),
					(45,  382,  false),
					(45,  385,  false),
					(45,  331,  false),
					(45,  335,  false),
					(45,  341,  false),
					(45,  583,  false),
					(45,  586,  false),
					(45,  589,  false),
					(45,  659,  false),
					(45,  719,  false),
					(45,  948,  false),
					(45,  920,  false),
					(45,  399,  false),
					(45,  402,  false),
					(45,  405,  false),
					(45,  338,  false),
					(45,  853,  false),
					(45,  11943,  false),
					(45,  11944,  false),
					(45,  856,  false),
					(45,  859,  false),
					(45,  862,  false),
					(45,  865,  false),
					(45,  868,  false),
					(45,  871,  false),
					(45,  299,  false),
					(45,  874,  false),
					(45,  877,  false),
					(45,  897,  false),
					(45,  884,  false),
					(45,  887,  false),
					(45,  12171,  false),
					(45,  12172,  false),
					(45,  12079,  false),
					(45,  12080,  false),
					(45,  894,  false),
					(45,  891,  false),
				});

				// DataValue, i=23, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				AddDefaultAddressSpaceNodeDataType(23, "DataValue", "DataValue", "Describes a value that is a structure containing a value, a status code and timestamps.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
				});

				// DiagnosticInfo, i=25, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- BaseDataType/24
				AddDefaultAddressSpaceNodeDataType(25, "DiagnosticInfo", "DiagnosticInfo", "Describes a value that is a structure containing diagnostics associated with a StatusCode.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  24,  true),
				});

				// Image, i=30, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- ByteString/15
				//	HasSubtype/45 -> ImageBMP/2000
				//	HasSubtype/45 -> ImageGIF/2001
				//	HasSubtype/45 -> ImageJPG/2002
				//	HasSubtype/45 -> ImagePNG/2003
				AddDefaultAddressSpaceNodeDataType(30, "Image", "Image", "Describes a value that is an image encoded as a string of bytes.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  15,  true),
					(45,  2000,  false),
					(45,  2001,  false),
					(45,  2002,  false),
					(45,  2003,  false),
				});

				// NamingRuleType, i=120, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumValues/12169
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(120, "NamingRuleType", "NamingRuleType", "Describes a value that specifies the significance of the BrowseName for an instance declaration.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  12169,  false),
					(45,  29,  true),
				});

				// ImageBMP, i=2000, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Image/30
				AddDefaultAddressSpaceNodeDataType(2000, "ImageBMP", "ImageBMP", "An image encoded in BMP format.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  30,  true),
				});

				// ImageGIF, i=2001, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Image/30
				AddDefaultAddressSpaceNodeDataType(2001, "ImageGIF", "ImageGIF", "An image encoded in GIF format.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  30,  true),
				});

				// ImageJPG, i=2002, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Image/30
				AddDefaultAddressSpaceNodeDataType(2002, "ImageJPG", "ImageJPG", "An image encoded in JPEG format.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  30,  true),
				});

				// ImagePNG, i=2003, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Image/30
				AddDefaultAddressSpaceNodeDataType(2003, "ImagePNG", "ImagePNG", "An image encoded in PNG format.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  30,  true),
				});

				// BitFieldMaskDataType, i=11737, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- UInt64/9
				AddDefaultAddressSpaceNodeDataType(11737, "BitFieldMaskDataType", "BitFieldMaskDataType", "A mask of 32 bits that can be updated individually by using the top 32 bits as a mask.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  9,  true),
				});

				// OpenFileMode, i=11939, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumValues/11940
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(11939, "OpenFileMode", "OpenFileMode", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11940,  false),
					(45,  29,  true),
				});

				// IdType, i=256, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumStrings/7591
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(256, "IdType", "IdType", "The type of identifier used in a node id.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  7591,  false),
					(45,  29,  true),
				});

				// NodeClass, i=257, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumValues/11878
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(257, "NodeClass", "NodeClass", "A mask specifying the class of the node.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11878,  false),
					(45,  29,  true),
				});

				// Argument, i=296, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/297
				//	HasEncoding/38 -> Default Binary/298
				AddDefaultAddressSpaceNodeDataType(296, "Argument", "Argument", "An argument for a method.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  297,  false),
					(38,  298,  false),
				});

				// EnumValueType, i=7594, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/7616
				//	HasEncoding/38 -> Default Binary/8251
				AddDefaultAddressSpaceNodeDataType(7594, "EnumValueType", "EnumValueType", "A mapping between a value of an enumerated type and a name and description.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  7616,  false),
					(38,  8251,  false),
				});

				// Duration, i=290, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Double/11
				AddDefaultAddressSpaceNodeDataType(290, "Duration", "Duration", "A period of time measured in seconds.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  11,  true),
				});

				// UtcTime, i=294, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- DateTime/13
				AddDefaultAddressSpaceNodeDataType(294, "UtcTime", "UtcTime", "A date/time value specified in Universal Coordinated Time (UTC).", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  13,  true),
				});

				// LocaleId, i=295, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- String/12
				AddDefaultAddressSpaceNodeDataType(295, "LocaleId", "LocaleId", "An identifier for a user locale.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  12,  true),
				});

				// TimeZoneDataType, i=8912, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/8913
				//	HasEncoding/38 -> Default Binary/8917
				AddDefaultAddressSpaceNodeDataType(8912, "TimeZoneDataType", "TimeZoneDataType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  8913,  false),
					(38,  8917,  false),
				});

				// IntegerId, i=288, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- UInt32/7
				AddDefaultAddressSpaceNodeDataType(288, "IntegerId", "IntegerId", "A numeric identifier for an object.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  7,  true),
				});

				// ApplicationType, i=307, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumStrings/7597
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(307, "ApplicationType", "ApplicationType", "The types of applications.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  7597,  false),
					(45,  29,  true),
				});

				// ApplicationDescription, i=308, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/309
				//	HasEncoding/38 -> Default Binary/310
				AddDefaultAddressSpaceNodeDataType(308, "ApplicationDescription", "ApplicationDescription", "Describes an application and how to find it.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  309,  false),
					(38,  310,  false),
				});

				// ApplicationInstanceCertificate, i=311, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- ByteString/15
				AddDefaultAddressSpaceNodeDataType(311, "ApplicationInstanceCertificate", "ApplicationInstanceCertificate", "A certificate for an instance of an application.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  15,  true),
				});

				// MessageSecurityMode, i=302, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumStrings/7595
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(302, "MessageSecurityMode", "MessageSecurityMode", "The type of security to use on a message.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  7595,  false),
					(45,  29,  true),
				});

				// UserTokenType, i=303, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumStrings/7596
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(303, "UserTokenType", "UserTokenType", "The possible user token types.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  7596,  false),
					(45,  29,  true),
				});

				// UserTokenPolicy, i=304, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/305
				//	HasEncoding/38 -> Default Binary/306
				AddDefaultAddressSpaceNodeDataType(304, "UserTokenPolicy", "UserTokenPolicy", "Describes a user token that can be used with a server.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  305,  false),
					(38,  306,  false),
				});

				// EndpointDescription, i=312, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/313
				//	HasEncoding/38 -> Default Binary/314
				AddDefaultAddressSpaceNodeDataType(312, "EndpointDescription", "EndpointDescription", "The description of a endpoint that can be used to access a server.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  313,  false),
					(38,  314,  false),
				});

				// RegisteredServer, i=432, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/433
				//	HasEncoding/38 -> Default Binary/434
				AddDefaultAddressSpaceNodeDataType(432, "RegisteredServer", "RegisteredServer", "The information required to register a server with a discovery server.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  433,  false),
					(38,  434,  false),
				});

				// SecurityTokenRequestType, i=315, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumStrings/7598
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(315, "SecurityTokenRequestType", "SecurityTokenRequestType", "Indicates whether a token if being created or renewed.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  7598,  false),
					(45,  29,  true),
				});

				// SignedSoftwareCertificate, i=344, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/345
				//	HasEncoding/38 -> Default Binary/346
				AddDefaultAddressSpaceNodeDataType(344, "SignedSoftwareCertificate", "SignedSoftwareCertificate", "A software certificate with a digital signature.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  345,  false),
					(38,  346,  false),
				});

				// SessionAuthenticationToken, i=388, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- NodeId/17
				AddDefaultAddressSpaceNodeDataType(388, "SessionAuthenticationToken", "SessionAuthenticationToken", "A unique identifier for a session used to authenticate requests.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  17,  true),
				});

				// UserIdentityToken, i=316, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasSubtype/45 -> AnonymousIdentityToken/319
				//	HasSubtype/45 -> UserNameIdentityToken/322
				//	HasSubtype/45 -> X509IdentityToken/325
				//	HasSubtype/45 -> IssuedIdentityToken/938
				//	HasEncoding/38 -> Default XML/317
				//	HasEncoding/38 -> Default Binary/318
				AddDefaultAddressSpaceNodeDataType(316, "UserIdentityToken", "UserIdentityToken", "A base type for a user identity token.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(45,  319,  false),
					(45,  322,  false),
					(45,  325,  false),
					(45,  938,  false),
					(38,  317,  false),
					(38,  318,  false),
				});

				// AnonymousIdentityToken, i=319, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- UserIdentityToken/316
				//	HasEncoding/38 -> Default XML/320
				//	HasEncoding/38 -> Default Binary/321
				AddDefaultAddressSpaceNodeDataType(319, "AnonymousIdentityToken", "AnonymousIdentityToken", "A token representing an anonymous user.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  316,  true),
					(38,  320,  false),
					(38,  321,  false),
				});

				// UserNameIdentityToken, i=322, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- UserIdentityToken/316
				//	HasEncoding/38 -> Default XML/323
				//	HasEncoding/38 -> Default Binary/324
				AddDefaultAddressSpaceNodeDataType(322, "UserNameIdentityToken", "UserNameIdentityToken", "A token representing a user identified by a user name and password.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  316,  true),
					(38,  323,  false),
					(38,  324,  false),
				});

				// X509IdentityToken, i=325, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- UserIdentityToken/316
				//	HasEncoding/38 -> Default XML/326
				//	HasEncoding/38 -> Default Binary/327
				AddDefaultAddressSpaceNodeDataType(325, "X509IdentityToken", "X509IdentityToken", "A token representing a user identified by an X509 certificate.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  316,  true),
					(38,  326,  false),
					(38,  327,  false),
				});

				// IssuedIdentityToken, i=938, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- UserIdentityToken/316
				//	HasEncoding/38 -> Default XML/939
				//	HasEncoding/38 -> Default Binary/940
				AddDefaultAddressSpaceNodeDataType(938, "IssuedIdentityToken", "IssuedIdentityToken", "A token representing a user identified by a WS-Security XML token.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  316,  true),
					(38,  939,  false),
					(38,  940,  false),
				});

				// NodeAttributesMask, i=348, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumValues/11881
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(348, "NodeAttributesMask", "NodeAttributesMask", "The bits used to specify default attributes for a new node.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11881,  false),
					(45,  29,  true),
				});

				// AddNodesItem, i=376, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/377
				//	HasEncoding/38 -> Default Binary/378
				AddDefaultAddressSpaceNodeDataType(376, "AddNodesItem", "AddNodesItem", "A request to add a node to the server address space.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  377,  false),
					(38,  378,  false),
				});

				// AddReferencesItem, i=379, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/380
				//	HasEncoding/38 -> Default Binary/381
				AddDefaultAddressSpaceNodeDataType(379, "AddReferencesItem", "AddReferencesItem", "A request to add a reference to the server address space.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  380,  false),
					(38,  381,  false),
				});

				// DeleteNodesItem, i=382, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/383
				//	HasEncoding/38 -> Default Binary/384
				AddDefaultAddressSpaceNodeDataType(382, "DeleteNodesItem", "DeleteNodesItem", "A request to delete a node to the server address space.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  383,  false),
					(38,  384,  false),
				});

				// DeleteReferencesItem, i=385, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/386
				//	HasEncoding/38 -> Default Binary/387
				AddDefaultAddressSpaceNodeDataType(385, "DeleteReferencesItem", "DeleteReferencesItem", "A request to delete a node from the server address space.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  386,  false),
					(38,  387,  false),
				});

				// AttributeWriteMask, i=347, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumValues/11882
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(347, "AttributeWriteMask", "AttributeWriteMask", "Define bits used to indicate which attributes are writeable.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11882,  false),
					(45,  29,  true),
				});

				// ContinuationPoint, i=521, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- ByteString/15
				AddDefaultAddressSpaceNodeDataType(521, "ContinuationPoint", "ContinuationPoint", "An identifier for a suspended query or browse operation.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  15,  true),
				});

				// Counter, i=289, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- UInt32/7
				AddDefaultAddressSpaceNodeDataType(289, "Counter", "Counter", "A monotonically increasing value.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  7,  true),
				});

				// NumericRange, i=291, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- String/12
				AddDefaultAddressSpaceNodeDataType(291, "NumericRange", "NumericRange", "Specifies a range of array indexes.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  12,  true),
				});

				// Time, i=292, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- String/12
				AddDefaultAddressSpaceNodeDataType(292, "Time", "Time", "A time value specified as HH:MM:SS.SSS.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  12,  true),
				});

				// Date, i=293, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- DateTime/13
				AddDefaultAddressSpaceNodeDataType(293, "Date", "Date", "A date value.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  13,  true),
				});

				// EndpointConfiguration, i=331, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/332
				//	HasEncoding/38 -> Default Binary/333
				AddDefaultAddressSpaceNodeDataType(331, "EndpointConfiguration", "EndpointConfiguration", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  332,  false),
					(38,  333,  false),
				});

				// ComplianceLevel, i=334, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumStrings/7599
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(334, "ComplianceLevel", "ComplianceLevel", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  7599,  false),
					(45,  29,  true),
				});

				// SupportedProfile, i=335, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/336
				//	HasEncoding/38 -> Default Binary/337
				AddDefaultAddressSpaceNodeDataType(335, "SupportedProfile", "SupportedProfile", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  336,  false),
					(38,  337,  false),
				});

				// SoftwareCertificate, i=341, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/342
				//	HasEncoding/38 -> Default Binary/343
				AddDefaultAddressSpaceNodeDataType(341, "SoftwareCertificate", "SoftwareCertificate", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  342,  false),
					(38,  343,  false),
				});

			}

			private void Part2()
			{
				// FilterOperator, i=576, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumStrings/7605
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(576, "FilterOperator", "FilterOperator", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  7605,  false),
					(45,  29,  true),
				});

				// ContentFilterElement, i=583, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/584
				//	HasEncoding/38 -> Default Binary/585
				AddDefaultAddressSpaceNodeDataType(583, "ContentFilterElement", "ContentFilterElement", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  584,  false),
					(38,  585,  false),
				});

				// ContentFilter, i=586, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/587
				//	HasEncoding/38 -> Default Binary/588
				AddDefaultAddressSpaceNodeDataType(586, "ContentFilter", "ContentFilter", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  587,  false),
					(38,  588,  false),
				});

				// FilterOperand, i=589, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasSubtype/45 -> ElementOperand/592
				//	HasSubtype/45 -> LiteralOperand/595
				//	HasSubtype/45 -> AttributeOperand/598
				//	HasSubtype/45 -> SimpleAttributeOperand/601
				//	HasEncoding/38 -> Default XML/590
				//	HasEncoding/38 -> Default Binary/591
				AddDefaultAddressSpaceNodeDataType(589, "FilterOperand", "FilterOperand", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(45,  592,  false),
					(45,  595,  false),
					(45,  598,  false),
					(45,  601,  false),
					(38,  590,  false),
					(38,  591,  false),
				});

				// ElementOperand, i=592, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- FilterOperand/589
				//	HasEncoding/38 -> Default XML/593
				//	HasEncoding/38 -> Default Binary/594
				AddDefaultAddressSpaceNodeDataType(592, "ElementOperand", "ElementOperand", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  589,  true),
					(38,  593,  false),
					(38,  594,  false),
				});

				// LiteralOperand, i=595, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- FilterOperand/589
				//	HasEncoding/38 -> Default XML/596
				//	HasEncoding/38 -> Default Binary/597
				AddDefaultAddressSpaceNodeDataType(595, "LiteralOperand", "LiteralOperand", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  589,  true),
					(38,  596,  false),
					(38,  597,  false),
				});

				// AttributeOperand, i=598, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- FilterOperand/589
				//	HasEncoding/38 -> Default XML/599
				//	HasEncoding/38 -> Default Binary/600
				AddDefaultAddressSpaceNodeDataType(598, "AttributeOperand", "AttributeOperand", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  589,  true),
					(38,  599,  false),
					(38,  600,  false),
				});

				// SimpleAttributeOperand, i=601, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- FilterOperand/589
				//	HasEncoding/38 -> Default XML/602
				//	HasEncoding/38 -> Default Binary/603
				AddDefaultAddressSpaceNodeDataType(601, "SimpleAttributeOperand", "SimpleAttributeOperand", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  589,  true),
					(38,  602,  false),
					(38,  603,  false),
				});

				// HistoryEvent, i=659, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/660
				//	HasEncoding/38 -> Default Binary/661
				AddDefaultAddressSpaceNodeDataType(659, "HistoryEvent", "HistoryEvent", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  660,  false),
					(38,  661,  false),
				});

				// HistoryUpdateType, i=11234, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumValues/11884
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(11234, "HistoryUpdateType", "HistoryUpdateType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11884,  false),
					(45,  29,  true),
				});

				// PerformUpdateType, i=11293, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumValues/11885
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(11293, "PerformUpdateType", "PerformUpdateType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11885,  false),
					(45,  29,  true),
				});

				// MonitoringFilter, i=719, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasSubtype/45 -> EventFilter/725
				//	HasEncoding/38 -> Default XML/720
				//	HasEncoding/38 -> Default Binary/721
				AddDefaultAddressSpaceNodeDataType(719, "MonitoringFilter", "MonitoringFilter", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(45,  725,  false),
					(38,  720,  false),
					(38,  721,  false),
				});

				// EventFilter, i=725, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- MonitoringFilter/719
				//	HasEncoding/38 -> Default XML/726
				//	HasEncoding/38 -> Default Binary/727
				AddDefaultAddressSpaceNodeDataType(725, "EventFilter", "EventFilter", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  719,  true),
					(38,  726,  false),
					(38,  727,  false),
				});

				// AggregateConfiguration, i=948, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/949
				//	HasEncoding/38 -> Default Binary/950
				AddDefaultAddressSpaceNodeDataType(948, "AggregateConfiguration", "AggregateConfiguration", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  949,  false),
					(38,  950,  false),
				});

				// HistoryEventFieldList, i=920, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/921
				//	HasEncoding/38 -> Default Binary/922
				AddDefaultAddressSpaceNodeDataType(920, "HistoryEventFieldList", "HistoryEventFieldList", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  921,  false),
					(38,  922,  false),
				});

				// EnumeratedTestType, i=398, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumValues/11886
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(398, "EnumeratedTestType", "EnumeratedTestType", "A simple enumerated type used for testing.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11886,  false),
					(45,  29,  true),
				});

				// ScalarTestType, i=399, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/400
				//	HasEncoding/38 -> Default Binary/401
				AddDefaultAddressSpaceNodeDataType(399, "ScalarTestType", "ScalarTestType", "A complex type containing all possible scalar types used for testing.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  400,  false),
					(38,  401,  false),
				});

				// ArrayTestType, i=402, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/403
				//	HasEncoding/38 -> Default Binary/404
				AddDefaultAddressSpaceNodeDataType(402, "ArrayTestType", "ArrayTestType", "A complex type containing all possible array types used for testing.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  403,  false),
					(38,  404,  false),
				});

				// CompositeTestType, i=405, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/406
				//	HasEncoding/38 -> Default Binary/407
				AddDefaultAddressSpaceNodeDataType(405, "CompositeTestType", "CompositeTestType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  406,  false),
					(38,  407,  false),
				});

				// BuildInfo, i=338, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/339
				//	HasEncoding/38 -> Default Binary/340
				AddDefaultAddressSpaceNodeDataType(338, "BuildInfo", "BuildInfo", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  339,  false),
					(38,  340,  false),
				});

				// RedundancySupport, i=851, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumStrings/7611
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(851, "RedundancySupport", "RedundancySupport", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  7611,  false),
					(45,  29,  true),
				});

				// ServerState, i=852, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumStrings/7612
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(852, "ServerState", "ServerState", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  7612,  false),
					(45,  29,  true),
				});

				// RedundantServerDataType, i=853, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/854
				//	HasEncoding/38 -> Default Binary/855
				AddDefaultAddressSpaceNodeDataType(853, "RedundantServerDataType", "RedundantServerDataType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  854,  false),
					(38,  855,  false),
				});

				// EndpointUrlListDataType, i=11943, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/11949
				//	HasEncoding/38 -> Default Binary/11957
				AddDefaultAddressSpaceNodeDataType(11943, "EndpointUrlListDataType", "EndpointUrlListDataType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  11949,  false),
					(38,  11957,  false),
				});

				// NetworkGroupDataType, i=11944, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/11950
				//	HasEncoding/38 -> Default Binary/11958
				AddDefaultAddressSpaceNodeDataType(11944, "NetworkGroupDataType", "NetworkGroupDataType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  11950,  false),
					(38,  11958,  false),
				});

				// SamplingIntervalDiagnosticsDataType, i=856, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/857
				//	HasEncoding/38 -> Default Binary/858
				AddDefaultAddressSpaceNodeDataType(856, "SamplingIntervalDiagnosticsDataType", "SamplingIntervalDiagnosticsDataType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  857,  false),
					(38,  858,  false),
				});

				// ServerDiagnosticsSummaryDataType, i=859, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/860
				//	HasEncoding/38 -> Default Binary/861
				AddDefaultAddressSpaceNodeDataType(859, "ServerDiagnosticsSummaryDataType", "ServerDiagnosticsSummaryDataType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  860,  false),
					(38,  861,  false),
				});

				// ServerStatusDataType, i=862, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/863
				//	HasEncoding/38 -> Default Binary/864
				AddDefaultAddressSpaceNodeDataType(862, "ServerStatusDataType", "ServerStatusDataType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  863,  false),
					(38,  864,  false),
				});

				// SessionDiagnosticsDataType, i=865, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/866
				//	HasEncoding/38 -> Default Binary/867
				AddDefaultAddressSpaceNodeDataType(865, "SessionDiagnosticsDataType", "SessionDiagnosticsDataType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  866,  false),
					(38,  867,  false),
				});

				// SessionSecurityDiagnosticsDataType, i=868, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/869
				//	HasEncoding/38 -> Default Binary/870
				AddDefaultAddressSpaceNodeDataType(868, "SessionSecurityDiagnosticsDataType", "SessionSecurityDiagnosticsDataType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  869,  false),
					(38,  870,  false),
				});

				// ServiceCounterDataType, i=871, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/872
				//	HasEncoding/38 -> Default Binary/873
				AddDefaultAddressSpaceNodeDataType(871, "ServiceCounterDataType", "ServiceCounterDataType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  872,  false),
					(38,  873,  false),
				});

				// StatusResult, i=299, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/300
				//	HasEncoding/38 -> Default Binary/301
				AddDefaultAddressSpaceNodeDataType(299, "StatusResult", "StatusResult", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  300,  false),
					(38,  301,  false),
				});

				// SubscriptionDiagnosticsDataType, i=874, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/875
				//	HasEncoding/38 -> Default Binary/876
				AddDefaultAddressSpaceNodeDataType(874, "SubscriptionDiagnosticsDataType", "SubscriptionDiagnosticsDataType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  875,  false),
					(38,  876,  false),
				});

				// ModelChangeStructureDataType, i=877, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/878
				//	HasEncoding/38 -> Default Binary/879
				AddDefaultAddressSpaceNodeDataType(877, "ModelChangeStructureDataType", "ModelChangeStructureDataType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  878,  false),
					(38,  879,  false),
				});

				// SemanticChangeStructureDataType, i=897, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/898
				//	HasEncoding/38 -> Default Binary/899
				AddDefaultAddressSpaceNodeDataType(897, "SemanticChangeStructureDataType", "SemanticChangeStructureDataType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  898,  false),
					(38,  899,  false),
				});

				// Range, i=884, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/885
				//	HasEncoding/38 -> Default Binary/886
				AddDefaultAddressSpaceNodeDataType(884, "Range", "Range", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  885,  false),
					(38,  886,  false),
				});

				// EUInformation, i=887, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/888
				//	HasEncoding/38 -> Default Binary/889
				AddDefaultAddressSpaceNodeDataType(887, "EUInformation", "EUInformation", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  888,  false),
					(38,  889,  false),
				});

				// AxisScaleEnumeration, i=12077, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumStrings/12078
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(12077, "AxisScaleEnumeration", "AxisScaleEnumeration", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  12078,  false),
					(45,  29,  true),
				});

				// ComplexNumberType, i=12171, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/12173
				//	HasEncoding/38 -> Default Binary/12181
				AddDefaultAddressSpaceNodeDataType(12171, "ComplexNumberType", "ComplexNumberType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  12173,  false),
					(38,  12181,  false),
				});

				// DoubleComplexNumberType, i=12172, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/12174
				//	HasEncoding/38 -> Default Binary/12182
				AddDefaultAddressSpaceNodeDataType(12172, "DoubleComplexNumberType", "DoubleComplexNumberType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  12174,  false),
					(38,  12182,  false),
				});

				// AxisInformation, i=12079, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/12081
				//	HasEncoding/38 -> Default Binary/12089
				AddDefaultAddressSpaceNodeDataType(12079, "AxisInformation", "AxisInformation", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  12081,  false),
					(38,  12089,  false),
				});

				// XVType, i=12080, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/12082
				//	HasEncoding/38 -> Default Binary/12090
				AddDefaultAddressSpaceNodeDataType(12080, "XVType", "XVType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  12082,  false),
					(38,  12090,  false),
				});

				// ProgramDiagnosticDataType, i=894, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/895
				//	HasEncoding/38 -> Default Binary/896
				AddDefaultAddressSpaceNodeDataType(894, "ProgramDiagnosticDataType", "ProgramDiagnosticDataType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  895,  false),
					(38,  896,  false),
				});

				// Annotation, i=891, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasSubtype/45 <- Structure/22
				//	HasEncoding/38 -> Default XML/892
				//	HasEncoding/38 -> Default Binary/893
				AddDefaultAddressSpaceNodeDataType(891, "Annotation", "Annotation", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  22,  true),
					(38,  892,  false),
					(38,  893,  false),
				});

				// ExceptionDeviationFormat, i=890, TypeGenerator.AddressSpaceGenerator+NodeDataType
				//	HasProperty/46 -> EnumStrings/7614
				//	HasSubtype/45 <- Enumeration/29
				AddDefaultAddressSpaceNodeDataType(890, "ExceptionDeviationFormat", "ExceptionDeviationFormat", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  7614,  false),
					(45,  29,  true),
				});

				// BaseObjectType, i=58, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 -> FolderType/61
				//	HasSubtype/45 -> DataTypeSystemType/75
				//	HasSubtype/45 -> DataTypeEncodingType/76
				//	HasSubtype/45 -> ModellingRuleType/77
				//	HasSubtype/45 -> ServerType/2004
				//	HasSubtype/45 -> ServerCapabilitiesType/2013
				//	HasSubtype/45 -> ServerDiagnosticsType/2020
				//	HasSubtype/45 -> SessionsDiagnosticsSummaryType/2026
				//	HasSubtype/45 -> SessionDiagnosticsObjectType/2029
				//	HasSubtype/45 -> VendorServerInfoType/2033
				//	HasSubtype/45 -> ServerRedundancyType/2034
				//	HasSubtype/45 -> OperationLimitsType/11564
				//	HasSubtype/45 -> FileType/11575
				//	HasSubtype/45 -> NamespaceMetadataType/11616
				//	HasSubtype/45 -> NamespacesType/11645
				//	HasSubtype/45 -> BaseEventType/2041
				//	HasSubtype/45 -> AggregateFunctionType/2340
				//	HasSubtype/45 -> StateMachineType/2299
				//	HasSubtype/45 -> StateType/2307
				//	HasSubtype/45 -> TransitionType/2310
				//	HasSubtype/45 -> BaseConditionClassType/11163
				//	HasSubtype/45 -> HistoricalDataConfigurationType/2318
				//	HasSubtype/45 -> HistoryServerCapabilitiesType/2330
				//	HasSubtype/45 -> AggregateConfigurationType/11187
				//	HasSubtype/45 -> LockType/8921
				AddDefaultAddressSpaceNodeObjectType(58, "BaseObjectType", "BaseObjectType", "The base type for all object nodes.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  61,  false),
					(45,  75,  false),
					(45,  76,  false),
					(45,  77,  false),
					(45,  2004,  false),
					(45,  2013,  false),
					(45,  2020,  false),
					(45,  2026,  false),
					(45,  2029,  false),
					(45,  2033,  false),
					(45,  2034,  false),
					(45,  11564,  false),
					(45,  11575,  false),
					(45,  11616,  false),
					(45,  11645,  false),
					(45,  2041,  false),
					(45,  2340,  false),
					(45,  2299,  false),
					(45,  2307,  false),
					(45,  2310,  false),
					(45,  11163,  false),
					(45,  2318,  false),
					(45,  2330,  false),
					(45,  11187,  false),
					(45,  8921,  false),
				});

				// FolderType, i=61, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(61, "FolderType", "FolderType", "The type for objects that organize other nodes.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  58,  true),
				});

				// DataTypeSystemType, i=75, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(75, "DataTypeSystemType", "DataTypeSystemType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  58,  true),
				});

				// DataTypeEncodingType, i=76, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(76, "DataTypeEncodingType", "DataTypeEncodingType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  58,  true),
				});

				// ModellingRuleType, i=77, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> NamingRule/111
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(77, "ModellingRuleType", "ModellingRuleType", "The type for an object that describes how an instance declaration is used when a type is instantiated.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  111,  false),
					(45,  58,  true),
				});

				// ServerType, i=2004, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> ServerArray/2005
				//	HasProperty/46 -> NamespaceArray/2006
				//	HasComponent/47 -> ServerStatus/2007
				//	HasProperty/46 -> ServiceLevel/2008
				//	HasProperty/46 -> Auditing/2742
				//	HasComponent/47 -> ServerCapabilities/2009
				//	HasComponent/47 -> ServerDiagnostics/2010
				//	HasComponent/47 -> VendorServerInfo/2011
				//	HasComponent/47 -> ServerRedundancy/2012
				//	HasComponent/47 -> Namespaces/11527
				//	HasComponent/47 -> GetMonitoredItems/11489
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(2004, "ServerType", "ServerType", "Specifies the current status and capabilities of the server.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2005,  false),
					(46,  2006,  false),
					(47,  2007,  false),
					(46,  2008,  false),
					(46,  2742,  false),
					(47,  2009,  false),
					(47,  2010,  false),
					(47,  2011,  false),
					(47,  2012,  false),
					(47,  11527,  false),
					(47,  11489,  false),
					(45,  58,  true),
				});

				// ServerCapabilitiesType, i=2013, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> ServerProfileArray/2014
				//	HasProperty/46 -> LocaleIdArray/2016
				//	HasProperty/46 -> MinSupportedSampleRate/2017
				//	HasProperty/46 -> MaxBrowseContinuationPoints/2732
				//	HasProperty/46 -> MaxQueryContinuationPoints/2733
				//	HasProperty/46 -> MaxHistoryContinuationPoints/2734
				//	HasProperty/46 -> SoftwareCertificates/3049
				//	HasProperty/46 -> MaxArrayLength/11549
				//	HasProperty/46 -> MaxStringLength/11550
				//	HasComponent/47 -> OperationLimits/11551
				//	HasComponent/47 -> ModellingRules/2019
				//	HasComponent/47 -> AggregateFunctions/2754
				//	HasComponent/47 -> <VendorCapability>/11562
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(2013, "ServerCapabilitiesType", "ServerCapabilitiesType", "Describes the capabilities supported by the server.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2014,  false),
					(46,  2016,  false),
					(46,  2017,  false),
					(46,  2732,  false),
					(46,  2733,  false),
					(46,  2734,  false),
					(46,  3049,  false),
					(46,  11549,  false),
					(46,  11550,  false),
					(47,  11551,  false),
					(47,  2019,  false),
					(47,  2754,  false),
					(47,  11562,  false),
					(45,  58,  true),
				});

				// ServerDiagnosticsType, i=2020, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> ServerDiagnosticsSummary/2021
				//	HasComponent/47 -> SamplingIntervalDiagnosticsArray/2022
				//	HasComponent/47 -> SubscriptionDiagnosticsArray/2023
				//	HasComponent/47 -> SessionsDiagnosticsSummary/2744
				//	HasProperty/46 -> EnabledFlag/2025
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(2020, "ServerDiagnosticsType", "ServerDiagnosticsType", "The diagnostics information for a server.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2021,  false),
					(47,  2022,  false),
					(47,  2023,  false),
					(47,  2744,  false),
					(46,  2025,  false),
					(45,  58,  true),
				});

				// SessionsDiagnosticsSummaryType, i=2026, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> SessionDiagnosticsArray/2027
				//	HasComponent/47 -> SessionSecurityDiagnosticsArray/2028
				//	HasComponent/47 -> <SessionPlaceholder>/12097
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(2026, "SessionsDiagnosticsSummaryType", "SessionsDiagnosticsSummaryType", "Provides a summary of session level diagnostics.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2027,  false),
					(47,  2028,  false),
					(47,  12097,  false),
					(45,  58,  true),
				});

				// SessionDiagnosticsObjectType, i=2029, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> SessionDiagnostics/2030
				//	HasComponent/47 -> SessionSecurityDiagnostics/2031
				//	HasComponent/47 -> SubscriptionDiagnosticsArray/2032
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(2029, "SessionDiagnosticsObjectType", "SessionDiagnosticsObjectType", "A container for session level diagnostics information.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2030,  false),
					(47,  2031,  false),
					(47,  2032,  false),
					(45,  58,  true),
				});

				// VendorServerInfoType, i=2033, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(2033, "VendorServerInfoType", "VendorServerInfoType", "A base type for vendor specific server information.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  58,  true),
				});

				// ServerRedundancyType, i=2034, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> RedundancySupport/2035
				//	HasSubtype/45 <- BaseObjectType/58
				//	HasSubtype/45 -> TransparentRedundancyType/2036
				//	HasSubtype/45 -> NonTransparentRedundancyType/2039
				AddDefaultAddressSpaceNodeObjectType(2034, "ServerRedundancyType", "ServerRedundancyType", "A base type for an object that describe how a server supports redundancy.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2035,  false),
					(45,  58,  true),
					(45,  2036,  false),
					(45,  2039,  false),
				});

				// TransparentRedundancyType, i=2036, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> CurrentServerId/2037
				//	HasProperty/46 -> RedundantServerArray/2038
				//	HasSubtype/45 <- ServerRedundancyType/2034
				AddDefaultAddressSpaceNodeObjectType(2036, "TransparentRedundancyType", "TransparentRedundancyType", "Identifies the capabilties of server that supports transparent redundancy.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2037,  false),
					(46,  2038,  false),
					(45,  2034,  true),
				});

				// NonTransparentRedundancyType, i=2039, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> ServerUriArray/2040
				//	HasSubtype/45 <- ServerRedundancyType/2034
				//	HasSubtype/45 -> NonTransparentNetworkRedundancyType/11945
				AddDefaultAddressSpaceNodeObjectType(2039, "NonTransparentRedundancyType", "NonTransparentRedundancyType", "Identifies the capabilties of server that supports non-transparent redundancy.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2040,  false),
					(45,  2034,  true),
					(45,  11945,  false),
				});

				// NonTransparentNetworkRedundancyType, i=11945, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> ServerNetworkGroups/11948
				//	HasSubtype/45 <- NonTransparentRedundancyType/2039
				AddDefaultAddressSpaceNodeObjectType(11945, "NonTransparentNetworkRedundancyType", "NonTransparentNetworkRedundancyType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11948,  false),
					(45,  2039,  true),
				});

				// OperationLimitsType, i=11564, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> MaxNodesPerRead/11565
				//	HasProperty/46 -> MaxNodesPerHistoryReadData/12161
				//	HasProperty/46 -> MaxNodesPerHistoryReadEvents/12162
				//	HasProperty/46 -> MaxNodesPerWrite/11567
				//	HasProperty/46 -> MaxNodesPerHistoryUpdateData/12163
				//	HasProperty/46 -> MaxNodesPerHistoryUpdateEvents/12164
				//	HasProperty/46 -> MaxNodesPerMethodCall/11569
				//	HasProperty/46 -> MaxNodesPerBrowse/11570
				//	HasProperty/46 -> MaxNodesPerRegisterNodes/11571
				//	HasProperty/46 -> MaxNodesPerTranslateBrowsePathsToNodeIds/11572
				//	HasProperty/46 -> MaxNodesPerNodeManagement/11573
				//	HasProperty/46 -> MaxMonitoredItemsPerCall/11574
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(11564, "OperationLimitsType", "OperationLimitsType", "Identifies the operation limits imposed by the server.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11565,  false),
					(46,  12161,  false),
					(46,  12162,  false),
					(46,  11567,  false),
					(46,  12163,  false),
					(46,  12164,  false),
					(46,  11569,  false),
					(46,  11570,  false),
					(46,  11571,  false),
					(46,  11572,  false),
					(46,  11573,  false),
					(46,  11574,  false),
					(45,  58,  true),
				});

				// FileType, i=11575, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> Size/11576
				//	HasProperty/46 -> Writeable/11577
				//	HasProperty/46 -> UserWriteable/11578
				//	HasProperty/46 -> OpenCount/11579
				//	HasComponent/47 -> Open/11580
				//	HasComponent/47 -> Close/11583
				//	HasComponent/47 -> Read/11585
				//	HasComponent/47 -> Write/11588
				//	HasComponent/47 -> GetPosition/11590
				//	HasComponent/47 -> SetPosition/11593
				//	HasSubtype/45 <- BaseObjectType/58
				//	HasSubtype/45 -> AddressSpaceFileType/11595
				AddDefaultAddressSpaceNodeObjectType(11575, "FileType", "FileType", "An object that represents a file that can be accessed via the server.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11576,  false),
					(46,  11577,  false),
					(46,  11578,  false),
					(46,  11579,  false),
					(47,  11580,  false),
					(47,  11583,  false),
					(47,  11585,  false),
					(47,  11588,  false),
					(47,  11590,  false),
					(47,  11593,  false),
					(45,  58,  true),
					(45,  11595,  false),
				});

				// AddressSpaceFileType, i=11595, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> ExportNamespace/11615
				//	HasSubtype/45 <- FileType/11575
				AddDefaultAddressSpaceNodeObjectType(11595, "AddressSpaceFileType", "AddressSpaceFileType", "A file used to store a namespace exported from the server.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  11615,  false),
					(45,  11575,  true),
				});

				// NamespaceMetadataType, i=11616, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> NamespaceUri/11617
				//	HasProperty/46 -> NamespaceVersion/11618
				//	HasProperty/46 -> NamespacePublicationDate/11619
				//	HasProperty/46 -> IsNamespaceSubset/11620
				//	HasProperty/46 -> StaticNodeIdIdentifierTypes/11621
				//	HasProperty/46 -> StaticNumericNodeIdRange/11622
				//	HasProperty/46 -> StaticStringNodeIdPattern/11623
				//	HasComponent/47 -> NamespaceFile/11624
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(11616, "NamespaceMetadataType", "NamespaceMetadataType", "Provides the metadata for a namespace used by the server.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11617,  false),
					(46,  11618,  false),
					(46,  11619,  false),
					(46,  11620,  false),
					(46,  11621,  false),
					(46,  11622,  false),
					(46,  11623,  false),
					(47,  11624,  false),
					(45,  58,  true),
				});

				// NamespacesType, i=11645, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> <NamespaceIdentifier>/11646
				//	HasComponent/47 -> AddressSpaceFile/11675
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(11645, "NamespacesType", "NamespacesType", "A container for the namespace metadata provided by the server.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  11646,  false),
					(47,  11675,  false),
					(45,  58,  true),
				});

				// BaseEventType, i=2041, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> EventId/2042
				//	HasProperty/46 -> EventType/2043
				//	HasProperty/46 -> SourceNode/2044
				//	HasProperty/46 -> SourceName/2045
				//	HasProperty/46 -> Time/2046
				//	HasProperty/46 -> ReceiveTime/2047
				//	HasProperty/46 -> LocalTime/3190
				//	HasProperty/46 -> Message/2050
				//	HasProperty/46 -> Severity/2051
				//	HasSubtype/45 <- BaseObjectType/58
				//	HasSubtype/45 -> AuditEventType/2052
				//	HasSubtype/45 -> SystemEventType/2130
				//	HasSubtype/45 -> BaseModelChangeEventType/2132
				//	HasSubtype/45 -> EventQueueOverflowEventType/3035
				//	HasSubtype/45 -> ProgressEventType/11436
				//	HasSubtype/45 -> TransitionEventType/2311
				//	HasSubtype/45 -> ConditionType/2782
				AddDefaultAddressSpaceNodeObjectType(2041, "BaseEventType", "BaseEventType", "The base type for all events.", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2042,  false),
					(46,  2043,  false),
					(46,  2044,  false),
					(46,  2045,  false),
					(46,  2046,  false),
					(46,  2047,  false),
					(46,  3190,  false),
					(46,  2050,  false),
					(46,  2051,  false),
					(45,  58,  true),
					(45,  2052,  false),
					(45,  2130,  false),
					(45,  2132,  false),
					(45,  3035,  false),
					(45,  11436,  false),
					(45,  2311,  false),
					(45,  2782,  false),
				});

				// AuditEventType, i=2052, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> ActionTimeStamp/2053
				//	HasProperty/46 -> Status/2054
				//	HasProperty/46 -> ServerId/2055
				//	HasProperty/46 -> ClientAuditEntryId/2056
				//	HasProperty/46 -> ClientUserId/2057
				//	HasSubtype/45 <- BaseEventType/2041
				//	HasSubtype/45 -> AuditSecurityEventType/2058
				//	HasSubtype/45 -> AuditSessionEventType/2069
				//	HasSubtype/45 -> AuditNodeManagementEventType/2090
				//	HasSubtype/45 -> AuditUpdateEventType/2099
				//	HasSubtype/45 -> AuditUpdateMethodEventType/2127
				AddDefaultAddressSpaceNodeObjectType(2052, "AuditEventType", "AuditEventType", "A base type for events used to track client initiated changes to the server state.", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2053,  false),
					(46,  2054,  false),
					(46,  2055,  false),
					(46,  2056,  false),
					(46,  2057,  false),
					(45,  2041,  true),
					(45,  2058,  false),
					(45,  2069,  false),
					(45,  2090,  false),
					(45,  2099,  false),
					(45,  2127,  false),
				});

				// AuditSecurityEventType, i=2058, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- AuditEventType/2052
				//	HasSubtype/45 -> AuditChannelEventType/2059
				//	HasSubtype/45 -> AuditCertificateEventType/2080
				AddDefaultAddressSpaceNodeObjectType(2058, "AuditSecurityEventType", "AuditSecurityEventType", "A base type for events used to track security related changes.", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2052,  true),
					(45,  2059,  false),
					(45,  2080,  false),
				});

				// AuditChannelEventType, i=2059, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> SecureChannelId/2745
				//	HasSubtype/45 <- AuditSecurityEventType/2058
				//	HasSubtype/45 -> AuditOpenSecureChannelEventType/2060
				AddDefaultAddressSpaceNodeObjectType(2059, "AuditChannelEventType", "AuditChannelEventType", "A base type for events used to track related changes to a secure channel.", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2745,  false),
					(45,  2058,  true),
					(45,  2060,  false),
				});

				// AuditOpenSecureChannelEventType, i=2060, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> ClientCertificate/2061
				//	HasProperty/46 -> ClientCertificateThumbprint/2746
				//	HasProperty/46 -> RequestType/2062
				//	HasProperty/46 -> SecurityPolicyUri/2063
				//	HasProperty/46 -> SecurityMode/2065
				//	HasProperty/46 -> RequestedLifetime/2066
				//	HasSubtype/45 <- AuditChannelEventType/2059
				AddDefaultAddressSpaceNodeObjectType(2060, "AuditOpenSecureChannelEventType", "AuditOpenSecureChannelEventType", "An event that is raised when a secure channel is opened.", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2061,  false),
					(46,  2746,  false),
					(46,  2062,  false),
					(46,  2063,  false),
					(46,  2065,  false),
					(46,  2066,  false),
					(45,  2059,  true),
				});

				// AuditSessionEventType, i=2069, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> SessionId/2070
				//	HasSubtype/45 <- AuditEventType/2052
				//	HasSubtype/45 -> AuditCreateSessionEventType/2071
				//	HasSubtype/45 -> AuditActivateSessionEventType/2075
				//	HasSubtype/45 -> AuditCancelEventType/2078
				AddDefaultAddressSpaceNodeObjectType(2069, "AuditSessionEventType", "AuditSessionEventType", "A base type for events used to track related changes to a session.", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2070,  false),
					(45,  2052,  true),
					(45,  2071,  false),
					(45,  2075,  false),
					(45,  2078,  false),
				});

				// AuditCreateSessionEventType, i=2071, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> SecureChannelId/2072
				//	HasProperty/46 -> ClientCertificate/2073
				//	HasProperty/46 -> ClientCertificateThumbprint/2747
				//	HasProperty/46 -> RevisedSessionTimeout/2074
				//	HasSubtype/45 <- AuditSessionEventType/2069
				//	HasSubtype/45 -> AuditUrlMismatchEventType/2748
				AddDefaultAddressSpaceNodeObjectType(2071, "AuditCreateSessionEventType", "AuditCreateSessionEventType", "An event that is raised when a session is created.", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2072,  false),
					(46,  2073,  false),
					(46,  2747,  false),
					(46,  2074,  false),
					(45,  2069,  true),
					(45,  2748,  false),
				});

				// AuditUrlMismatchEventType, i=2748, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> EndpointUrl/2749
				//	HasSubtype/45 <- AuditCreateSessionEventType/2071
				AddDefaultAddressSpaceNodeObjectType(2748, "AuditUrlMismatchEventType", "AuditUrlMismatchEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2749,  false),
					(45,  2071,  true),
				});

				// AuditActivateSessionEventType, i=2075, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> ClientSoftwareCertificates/2076
				//	HasProperty/46 -> UserIdentityToken/2077
				//	HasProperty/46 -> SecureChannelId/11485
				//	HasSubtype/45 <- AuditSessionEventType/2069
				AddDefaultAddressSpaceNodeObjectType(2075, "AuditActivateSessionEventType", "AuditActivateSessionEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2076,  false),
					(46,  2077,  false),
					(46,  11485,  false),
					(45,  2069,  true),
				});

				// AuditCancelEventType, i=2078, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> RequestHandle/2079
				//	HasSubtype/45 <- AuditSessionEventType/2069
				AddDefaultAddressSpaceNodeObjectType(2078, "AuditCancelEventType", "AuditCancelEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2079,  false),
					(45,  2069,  true),
				});

				// AuditCertificateEventType, i=2080, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> Certificate/2081
				//	HasSubtype/45 <- AuditSecurityEventType/2058
				//	HasSubtype/45 -> AuditCertificateDataMismatchEventType/2082
				//	HasSubtype/45 -> AuditCertificateExpiredEventType/2085
				//	HasSubtype/45 -> AuditCertificateInvalidEventType/2086
				//	HasSubtype/45 -> AuditCertificateUntrustedEventType/2087
				//	HasSubtype/45 -> AuditCertificateRevokedEventType/2088
				//	HasSubtype/45 -> AuditCertificateMismatchEventType/2089
				AddDefaultAddressSpaceNodeObjectType(2080, "AuditCertificateEventType", "AuditCertificateEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2081,  false),
					(45,  2058,  true),
					(45,  2082,  false),
					(45,  2085,  false),
					(45,  2086,  false),
					(45,  2087,  false),
					(45,  2088,  false),
					(45,  2089,  false),
				});

				// AuditCertificateDataMismatchEventType, i=2082, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> InvalidHostname/2083
				//	HasProperty/46 -> InvalidUri/2084
				//	HasSubtype/45 <- AuditCertificateEventType/2080
				AddDefaultAddressSpaceNodeObjectType(2082, "AuditCertificateDataMismatchEventType", "AuditCertificateDataMismatchEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2083,  false),
					(46,  2084,  false),
					(45,  2080,  true),
				});

				// AuditCertificateExpiredEventType, i=2085, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- AuditCertificateEventType/2080
				AddDefaultAddressSpaceNodeObjectType(2085, "AuditCertificateExpiredEventType", "AuditCertificateExpiredEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2080,  true),
				});

				// AuditCertificateInvalidEventType, i=2086, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- AuditCertificateEventType/2080
				AddDefaultAddressSpaceNodeObjectType(2086, "AuditCertificateInvalidEventType", "AuditCertificateInvalidEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2080,  true),
				});

				// AuditCertificateUntrustedEventType, i=2087, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- AuditCertificateEventType/2080
				AddDefaultAddressSpaceNodeObjectType(2087, "AuditCertificateUntrustedEventType", "AuditCertificateUntrustedEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2080,  true),
				});

				// AuditCertificateRevokedEventType, i=2088, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- AuditCertificateEventType/2080
				AddDefaultAddressSpaceNodeObjectType(2088, "AuditCertificateRevokedEventType", "AuditCertificateRevokedEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2080,  true),
				});

				// AuditCertificateMismatchEventType, i=2089, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- AuditCertificateEventType/2080
				AddDefaultAddressSpaceNodeObjectType(2089, "AuditCertificateMismatchEventType", "AuditCertificateMismatchEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2080,  true),
				});

				// AuditNodeManagementEventType, i=2090, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- AuditEventType/2052
				//	HasSubtype/45 -> AuditAddNodesEventType/2091
				//	HasSubtype/45 -> AuditDeleteNodesEventType/2093
				//	HasSubtype/45 -> AuditAddReferencesEventType/2095
				//	HasSubtype/45 -> AuditDeleteReferencesEventType/2097
				AddDefaultAddressSpaceNodeObjectType(2090, "AuditNodeManagementEventType", "AuditNodeManagementEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2052,  true),
					(45,  2091,  false),
					(45,  2093,  false),
					(45,  2095,  false),
					(45,  2097,  false),
				});

				// AuditAddNodesEventType, i=2091, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> NodesToAdd/2092
				//	HasSubtype/45 <- AuditNodeManagementEventType/2090
				AddDefaultAddressSpaceNodeObjectType(2091, "AuditAddNodesEventType", "AuditAddNodesEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2092,  false),
					(45,  2090,  true),
				});

			}
			private void Part3()
			{
				// AuditDeleteNodesEventType, i=2093, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> NodesToDelete/2094
				//	HasSubtype/45 <- AuditNodeManagementEventType/2090
				AddDefaultAddressSpaceNodeObjectType(2093, "AuditDeleteNodesEventType", "AuditDeleteNodesEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2094,  false),
					(45,  2090,  true),
				});

				// AuditAddReferencesEventType, i=2095, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> ReferencesToAdd/2096
				//	HasSubtype/45 <- AuditNodeManagementEventType/2090
				AddDefaultAddressSpaceNodeObjectType(2095, "AuditAddReferencesEventType", "AuditAddReferencesEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2096,  false),
					(45,  2090,  true),
				});

				// AuditDeleteReferencesEventType, i=2097, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> ReferencesToDelete/2098
				//	HasSubtype/45 <- AuditNodeManagementEventType/2090
				AddDefaultAddressSpaceNodeObjectType(2097, "AuditDeleteReferencesEventType", "AuditDeleteReferencesEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2098,  false),
					(45,  2090,  true),
				});

				// AuditUpdateEventType, i=2099, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- AuditEventType/2052
				//	HasSubtype/45 -> AuditWriteUpdateEventType/2100
				//	HasSubtype/45 -> AuditHistoryUpdateEventType/2104
				AddDefaultAddressSpaceNodeObjectType(2099, "AuditUpdateEventType", "AuditUpdateEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2052,  true),
					(45,  2100,  false),
					(45,  2104,  false),
				});

				// AuditWriteUpdateEventType, i=2100, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> AttributeId/2750
				//	HasProperty/46 -> IndexRange/2101
				//	HasProperty/46 -> OldValue/2102
				//	HasProperty/46 -> NewValue/2103
				//	HasSubtype/45 <- AuditUpdateEventType/2099
				AddDefaultAddressSpaceNodeObjectType(2100, "AuditWriteUpdateEventType", "AuditWriteUpdateEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2750,  false),
					(46,  2101,  false),
					(46,  2102,  false),
					(46,  2103,  false),
					(45,  2099,  true),
				});

				// AuditHistoryUpdateEventType, i=2104, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> ParameterDataTypeId/2751
				//	HasSubtype/45 <- AuditUpdateEventType/2099
				//	HasSubtype/45 -> AuditHistoryEventUpdateEventType/2999
				//	HasSubtype/45 -> AuditHistoryValueUpdateEventType/3006
				//	HasSubtype/45 -> AuditHistoryDeleteEventType/3012
				AddDefaultAddressSpaceNodeObjectType(2104, "AuditHistoryUpdateEventType", "AuditHistoryUpdateEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2751,  false),
					(45,  2099,  true),
					(45,  2999,  false),
					(45,  3006,  false),
					(45,  3012,  false),
				});

				// AuditUpdateMethodEventType, i=2127, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> MethodId/2128
				//	HasProperty/46 -> InputArguments/2129
				//	HasSubtype/45 <- AuditEventType/2052
				//	HasSubtype/45 -> AuditUpdateStateEventType/2315
				//	HasSubtype/45 -> AuditConditionEventType/2790
				AddDefaultAddressSpaceNodeObjectType(2127, "AuditUpdateMethodEventType", "AuditUpdateMethodEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2128,  false),
					(46,  2129,  false),
					(45,  2052,  true),
					(45,  2315,  false),
					(45,  2790,  false),
				});

				// SystemEventType, i=2130, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- BaseEventType/2041
				//	HasSubtype/45 -> DeviceFailureEventType/2131
				//	HasSubtype/45 -> SystemStatusChangeEventType/11446
				//	HasSubtype/45 -> RefreshStartEventType/2787
				//	HasSubtype/45 -> RefreshEndEventType/2788
				//	HasSubtype/45 -> RefreshRequiredEventType/2789
				AddDefaultAddressSpaceNodeObjectType(2130, "SystemEventType", "SystemEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2041,  true),
					(45,  2131,  false),
					(45,  11446,  false),
					(45,  2787,  false),
					(45,  2788,  false),
					(45,  2789,  false),
				});

				// DeviceFailureEventType, i=2131, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- SystemEventType/2130
				AddDefaultAddressSpaceNodeObjectType(2131, "DeviceFailureEventType", "DeviceFailureEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2130,  true),
				});

				// SystemStatusChangeEventType, i=11446, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> SystemState/11696
				//	HasSubtype/45 <- SystemEventType/2130
				AddDefaultAddressSpaceNodeObjectType(11446, "SystemStatusChangeEventType", "SystemStatusChangeEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11696,  false),
					(45,  2130,  true),
				});

				// BaseModelChangeEventType, i=2132, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- BaseEventType/2041
				//	HasSubtype/45 -> GeneralModelChangeEventType/2133
				//	HasSubtype/45 -> SemanticChangeEventType/2738
				AddDefaultAddressSpaceNodeObjectType(2132, "BaseModelChangeEventType", "BaseModelChangeEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2041,  true),
					(45,  2133,  false),
					(45,  2738,  false),
				});

				// GeneralModelChangeEventType, i=2133, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> Changes/2134
				//	HasSubtype/45 <- BaseModelChangeEventType/2132
				AddDefaultAddressSpaceNodeObjectType(2133, "GeneralModelChangeEventType", "GeneralModelChangeEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2134,  false),
					(45,  2132,  true),
				});

				// SemanticChangeEventType, i=2738, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> Changes/2739
				//	HasSubtype/45 <- BaseModelChangeEventType/2132
				AddDefaultAddressSpaceNodeObjectType(2738, "SemanticChangeEventType", "SemanticChangeEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2739,  false),
					(45,  2132,  true),
				});

				// EventQueueOverflowEventType, i=3035, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- BaseEventType/2041
				AddDefaultAddressSpaceNodeObjectType(3035, "EventQueueOverflowEventType", "EventQueueOverflowEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2041,  true),
				});

				// ProgressEventType, i=11436, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- BaseEventType/2041
				AddDefaultAddressSpaceNodeObjectType(11436, "ProgressEventType", "ProgressEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2041,  true),
				});

				// AggregateFunctionType, i=2340, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(2340, "AggregateFunctionType", "AggregateFunctionType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  58,  true),
				});

				// StateMachineType, i=2299, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> CurrentState/2769
				//	HasComponent/47 -> LastTransition/2770
				//	HasSubtype/45 <- BaseObjectType/58
				//	HasSubtype/45 -> FiniteStateMachineType/2771
				AddDefaultAddressSpaceNodeObjectType(2299, "StateMachineType", "StateMachineType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2769,  false),
					(47,  2770,  false),
					(45,  58,  true),
					(45,  2771,  false),
				});

				// FiniteStateMachineType, i=2771, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> CurrentState/2772
				//	HasComponent/47 -> LastTransition/2773
				//	HasSubtype/45 <- StateMachineType/2299
				//	HasSubtype/45 -> ShelvedStateMachineType/2929
				//	HasSubtype/45 -> ExclusiveLimitStateMachineType/9318
				//	HasSubtype/45 -> ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObjectType(2771, "FiniteStateMachineType", "FiniteStateMachineType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2772,  false),
					(47,  2773,  false),
					(45,  2299,  true),
					(45,  2929,  false),
					(45,  9318,  false),
					(45,  2391,  false),
				});

				// StateType, i=2307, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> StateNumber/2308
				//	HasSubtype/45 <- BaseObjectType/58
				//	HasSubtype/45 -> InitialStateType/2309
				AddDefaultAddressSpaceNodeObjectType(2307, "StateType", "StateType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2308,  false),
					(45,  58,  true),
					(45,  2309,  false),
				});

				// InitialStateType, i=2309, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- StateType/2307
				AddDefaultAddressSpaceNodeObjectType(2309, "InitialStateType", "InitialStateType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2307,  true),
				});

				// TransitionType, i=2310, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> TransitionNumber/2312
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(2310, "TransitionType", "TransitionType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2312,  false),
					(45,  58,  true),
				});

				// TransitionEventType, i=2311, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> Transition/2774
				//	HasComponent/47 -> FromState/2775
				//	HasComponent/47 -> ToState/2776
				//	HasSubtype/45 <- BaseEventType/2041
				//	HasSubtype/45 -> ProgramTransitionEventType/2378
				AddDefaultAddressSpaceNodeObjectType(2311, "TransitionEventType", "TransitionEventType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2774,  false),
					(47,  2775,  false),
					(47,  2776,  false),
					(45,  2041,  true),
					(45,  2378,  false),
				});

				// AuditUpdateStateEventType, i=2315, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> OldStateId/2777
				//	HasProperty/46 -> NewStateId/2778
				//	HasSubtype/45 <- AuditUpdateMethodEventType/2127
				//	HasSubtype/45 -> AuditProgramTransitionEventType/11856
				//	HasSubtype/45 -> ProgramTransitionAuditEventType/3806
				AddDefaultAddressSpaceNodeObjectType(2315, "AuditUpdateStateEventType", "AuditUpdateStateEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2777,  false),
					(46,  2778,  false),
					(45,  2127,  true),
					(45,  11856,  false),
					(45,  3806,  false),
				});

				// ConditionType, i=2782, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> ConditionClassId/11112
				//	HasProperty/46 -> ConditionClassName/11113
				//	HasProperty/46 -> ConditionName/9009
				//	HasProperty/46 -> BranchId/9010
				//	HasProperty/46 -> Retain/3874
				//	HasComponent/47 -> EnabledState/9011
				//	HasComponent/47 -> Quality/9020
				//	HasComponent/47 -> LastSeverity/9022
				//	HasComponent/47 -> Comment/9024
				//	HasProperty/46 -> ClientUserId/9026
				//	HasComponent/47 -> Disable/9028
				//	HasComponent/47 -> Enable/9027
				//	HasComponent/47 -> AddComment/9029
				//	HasComponent/47 -> ConditionRefresh/3875
				//	HasSubtype/45 <- BaseEventType/2041
				//	HasSubtype/45 -> DialogConditionType/2830
				//	HasSubtype/45 -> AcknowledgeableConditionType/2881
				AddDefaultAddressSpaceNodeObjectType(2782, "ConditionType", "ConditionType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11112,  false),
					(46,  11113,  false),
					(46,  9009,  false),
					(46,  9010,  false),
					(46,  3874,  false),
					(47,  9011,  false),
					(47,  9020,  false),
					(47,  9022,  false),
					(47,  9024,  false),
					(46,  9026,  false),
					(47,  9028,  false),
					(47,  9027,  false),
					(47,  9029,  false),
					(47,  3875,  false),
					(45,  2041,  true),
					(45,  2830,  false),
					(45,  2881,  false),
				});

				// DialogConditionType, i=2830, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> EnabledState/9035
				//	HasComponent/47 -> DialogState/9055
				//	HasProperty/46 -> Prompt/2831
				//	HasProperty/46 -> ResponseOptionSet/9064
				//	HasProperty/46 -> DefaultResponse/9065
				//	HasProperty/46 -> OkResponse/9066
				//	HasProperty/46 -> CancelResponse/9067
				//	HasProperty/46 -> LastResponse/9068
				//	HasComponent/47 -> Respond/9069
				//	HasSubtype/45 <- ConditionType/2782
				AddDefaultAddressSpaceNodeObjectType(2830, "DialogConditionType", "DialogConditionType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  9035,  false),
					(47,  9055,  false),
					(46,  2831,  false),
					(46,  9064,  false),
					(46,  9065,  false),
					(46,  9066,  false),
					(46,  9067,  false),
					(46,  9068,  false),
					(47,  9069,  false),
					(45,  2782,  true),
				});

				// AcknowledgeableConditionType, i=2881, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> EnabledState/9073
				//	HasComponent/47 -> AckedState/9093
				//	HasComponent/47 -> ConfirmedState/9102
				//	HasComponent/47 -> Acknowledge/9111
				//	HasComponent/47 -> Confirm/9113
				//	HasSubtype/45 <- ConditionType/2782
				//	HasSubtype/45 -> AlarmConditionType/2915
				AddDefaultAddressSpaceNodeObjectType(2881, "AcknowledgeableConditionType", "AcknowledgeableConditionType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  9073,  false),
					(47,  9093,  false),
					(47,  9102,  false),
					(47,  9111,  false),
					(47,  9113,  false),
					(45,  2782,  true),
					(45,  2915,  false),
				});

				// AlarmConditionType, i=2915, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> EnabledState/9118
				//	HasComponent/47 -> ActiveState/9160
				//	HasProperty/46 -> InputNode/11120
				//	HasComponent/47 -> SuppressedState/9169
				//	HasComponent/47 -> ShelvingState/9178
				//	HasProperty/46 -> SuppressedOrShelved/9215
				//	HasProperty/46 -> MaxTimeShelved/9216
				//	HasSubtype/45 <- AcknowledgeableConditionType/2881
				//	HasSubtype/45 -> LimitAlarmType/2955
				//	HasSubtype/45 -> DiscreteAlarmType/10523
				AddDefaultAddressSpaceNodeObjectType(2915, "AlarmConditionType", "AlarmConditionType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  9118,  false),
					(47,  9160,  false),
					(46,  11120,  false),
					(47,  9169,  false),
					(47,  9178,  false),
					(46,  9215,  false),
					(46,  9216,  false),
					(45,  2881,  true),
					(45,  2955,  false),
					(45,  10523,  false),
				});

				// ShelvedStateMachineType, i=2929, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> UnshelveTime/9115
				//	HasComponent/47 -> Unshelved/2930
				//	HasComponent/47 -> TimedShelved/2932
				//	HasComponent/47 -> OneShotShelved/2933
				//	HasComponent/47 -> UnshelvedToTimedShelved/2935
				//	HasComponent/47 -> UnshelvedToOneShotShelved/2936
				//	HasComponent/47 -> TimedShelvedToUnshelved/2940
				//	HasComponent/47 -> TimedShelvedToOneShotShelved/2942
				//	HasComponent/47 -> OneShotShelvedToUnshelved/2943
				//	HasComponent/47 -> OneShotShelvedToTimedShelved/2945
				//	HasComponent/47 -> Unshelve/2947
				//	HasComponent/47 -> OneShotShelve/2948
				//	HasComponent/47 -> TimedShelve/2949
				//	HasSubtype/45 <- FiniteStateMachineType/2771
				AddDefaultAddressSpaceNodeObjectType(2929, "ShelvedStateMachineType", "ShelvedStateMachineType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9115,  false),
					(47,  2930,  false),
					(47,  2932,  false),
					(47,  2933,  false),
					(47,  2935,  false),
					(47,  2936,  false),
					(47,  2940,  false),
					(47,  2942,  false),
					(47,  2943,  false),
					(47,  2945,  false),
					(47,  2947,  false),
					(47,  2948,  false),
					(47,  2949,  false),
					(45,  2771,  true),
				});

				// LimitAlarmType, i=2955, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> HighHighLimit/11124
				//	HasProperty/46 -> HighLimit/11125
				//	HasProperty/46 -> LowLimit/11126
				//	HasProperty/46 -> LowLowLimit/11127
				//	HasSubtype/45 <- AlarmConditionType/2915
				//	HasSubtype/45 -> ExclusiveLimitAlarmType/9341
				//	HasSubtype/45 -> NonExclusiveLimitAlarmType/9906
				AddDefaultAddressSpaceNodeObjectType(2955, "LimitAlarmType", "LimitAlarmType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11124,  false),
					(46,  11125,  false),
					(46,  11126,  false),
					(46,  11127,  false),
					(45,  2915,  true),
					(45,  9341,  false),
					(45,  9906,  false),
				});

				// ExclusiveLimitStateMachineType, i=9318, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> HighHigh/9329
				//	HasComponent/47 -> High/9331
				//	HasComponent/47 -> Low/9333
				//	HasComponent/47 -> LowLow/9335
				//	HasComponent/47 -> LowLowToLow/9337
				//	HasComponent/47 -> LowToLowLow/9338
				//	HasComponent/47 -> HighHighToHigh/9339
				//	HasComponent/47 -> HighToHighHigh/9340
				//	HasSubtype/45 <- FiniteStateMachineType/2771
				AddDefaultAddressSpaceNodeObjectType(9318, "ExclusiveLimitStateMachineType", "ExclusiveLimitStateMachineType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  9329,  false),
					(47,  9331,  false),
					(47,  9333,  false),
					(47,  9335,  false),
					(47,  9337,  false),
					(47,  9338,  false),
					(47,  9339,  false),
					(47,  9340,  false),
					(45,  2771,  true),
				});

				// ExclusiveLimitAlarmType, i=9341, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> ActiveState/9398
				//	HasComponent/47 -> LimitState/9455
				//	HasSubtype/45 <- LimitAlarmType/2955
				//	HasSubtype/45 -> ExclusiveLevelAlarmType/9482
				//	HasSubtype/45 -> ExclusiveDeviationAlarmType/9764
				//	HasSubtype/45 -> ExclusiveRateOfChangeAlarmType/9623
				AddDefaultAddressSpaceNodeObjectType(9341, "ExclusiveLimitAlarmType", "ExclusiveLimitAlarmType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  9398,  false),
					(47,  9455,  false),
					(45,  2955,  true),
					(45,  9482,  false),
					(45,  9764,  false),
					(45,  9623,  false),
				});

				// NonExclusiveLimitAlarmType, i=9906, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> ActiveState/9963
				//	HasComponent/47 -> HighHighState/10020
				//	HasComponent/47 -> HighState/10029
				//	HasComponent/47 -> LowState/10038
				//	HasComponent/47 -> LowLowState/10047
				//	HasSubtype/45 <- LimitAlarmType/2955
				//	HasSubtype/45 -> NonExclusiveLevelAlarmType/10060
				//	HasSubtype/45 -> NonExclusiveDeviationAlarmType/10368
				//	HasSubtype/45 -> NonExclusiveRateOfChangeAlarmType/10214
				AddDefaultAddressSpaceNodeObjectType(9906, "NonExclusiveLimitAlarmType", "NonExclusiveLimitAlarmType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  9963,  false),
					(47,  10020,  false),
					(47,  10029,  false),
					(47,  10038,  false),
					(47,  10047,  false),
					(45,  2955,  true),
					(45,  10060,  false),
					(45,  10368,  false),
					(45,  10214,  false),
				});

				// NonExclusiveLevelAlarmType, i=10060, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- NonExclusiveLimitAlarmType/9906
				AddDefaultAddressSpaceNodeObjectType(10060, "NonExclusiveLevelAlarmType", "NonExclusiveLevelAlarmType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  9906,  true),
				});

				// ExclusiveLevelAlarmType, i=9482, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- ExclusiveLimitAlarmType/9341
				AddDefaultAddressSpaceNodeObjectType(9482, "ExclusiveLevelAlarmType", "ExclusiveLevelAlarmType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  9341,  true),
				});

				// NonExclusiveDeviationAlarmType, i=10368, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> SetpointNode/10522
				//	HasSubtype/45 <- NonExclusiveLimitAlarmType/9906
				AddDefaultAddressSpaceNodeObjectType(10368, "NonExclusiveDeviationAlarmType", "NonExclusiveDeviationAlarmType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  10522,  false),
					(45,  9906,  true),
				});

				// ExclusiveDeviationAlarmType, i=9764, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> SetpointNode/9905
				//	HasSubtype/45 <- ExclusiveLimitAlarmType/9341
				AddDefaultAddressSpaceNodeObjectType(9764, "ExclusiveDeviationAlarmType", "ExclusiveDeviationAlarmType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9905,  false),
					(45,  9341,  true),
				});

				// NonExclusiveRateOfChangeAlarmType, i=10214, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- NonExclusiveLimitAlarmType/9906
				AddDefaultAddressSpaceNodeObjectType(10214, "NonExclusiveRateOfChangeAlarmType", "NonExclusiveRateOfChangeAlarmType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  9906,  true),
				});

				// ExclusiveRateOfChangeAlarmType, i=9623, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- ExclusiveLimitAlarmType/9341
				AddDefaultAddressSpaceNodeObjectType(9623, "ExclusiveRateOfChangeAlarmType", "ExclusiveRateOfChangeAlarmType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  9341,  true),
				});

				// DiscreteAlarmType, i=10523, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- AlarmConditionType/2915
				//	HasSubtype/45 -> OffNormalAlarmType/10637
				AddDefaultAddressSpaceNodeObjectType(10523, "DiscreteAlarmType", "DiscreteAlarmType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2915,  true),
					(45,  10637,  false),
				});

				// OffNormalAlarmType, i=10637, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> NormalState/11158
				//	HasSubtype/45 <- DiscreteAlarmType/10523
				//	HasSubtype/45 -> SystemOffNormalAlarmType/11753
				//	HasSubtype/45 -> TripAlarmType/10751
				AddDefaultAddressSpaceNodeObjectType(10637, "OffNormalAlarmType", "OffNormalAlarmType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11158,  false),
					(45,  10523,  true),
					(45,  11753,  false),
					(45,  10751,  false),
				});

				// SystemOffNormalAlarmType, i=11753, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- OffNormalAlarmType/10637
				AddDefaultAddressSpaceNodeObjectType(11753, "SystemOffNormalAlarmType", "SystemOffNormalAlarmType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  10637,  true),
				});

				// TripAlarmType, i=10751, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- OffNormalAlarmType/10637
				AddDefaultAddressSpaceNodeObjectType(10751, "TripAlarmType", "TripAlarmType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  10637,  true),
				});

				// BaseConditionClassType, i=11163, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- BaseObjectType/58
				//	HasSubtype/45 -> ProcessConditionClassType/11164
				//	HasSubtype/45 -> MaintenanceConditionClassType/11165
				//	HasSubtype/45 -> SystemConditionClassType/11166
				AddDefaultAddressSpaceNodeObjectType(11163, "BaseConditionClassType", "BaseConditionClassType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  58,  true),
					(45,  11164,  false),
					(45,  11165,  false),
					(45,  11166,  false),
				});

				// ProcessConditionClassType, i=11164, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- BaseConditionClassType/11163
				AddDefaultAddressSpaceNodeObjectType(11164, "ProcessConditionClassType", "ProcessConditionClassType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  11163,  true),
				});

				// MaintenanceConditionClassType, i=11165, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- BaseConditionClassType/11163
				AddDefaultAddressSpaceNodeObjectType(11165, "MaintenanceConditionClassType", "MaintenanceConditionClassType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  11163,  true),
				});

				// SystemConditionClassType, i=11166, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- BaseConditionClassType/11163
				AddDefaultAddressSpaceNodeObjectType(11166, "SystemConditionClassType", "SystemConditionClassType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  11163,  true),
				});

				// AuditConditionEventType, i=2790, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- AuditUpdateMethodEventType/2127
				//	HasSubtype/45 -> AuditConditionEnableEventType/2803
				//	HasSubtype/45 -> AuditConditionCommentEventType/2829
				//	HasSubtype/45 -> AuditConditionRespondEventType/8927
				//	HasSubtype/45 -> AuditConditionAcknowledgeEventType/8944
				//	HasSubtype/45 -> AuditConditionConfirmEventType/8961
				//	HasSubtype/45 -> AuditConditionShelvingEventType/11093
				AddDefaultAddressSpaceNodeObjectType(2790, "AuditConditionEventType", "AuditConditionEventType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2127,  true),
					(45,  2803,  false),
					(45,  2829,  false),
					(45,  8927,  false),
					(45,  8944,  false),
					(45,  8961,  false),
					(45,  11093,  false),
				});

				// AuditConditionEnableEventType, i=2803, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- AuditConditionEventType/2790
				AddDefaultAddressSpaceNodeObjectType(2803, "AuditConditionEnableEventType", "AuditConditionEnableEventType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2790,  true),
				});

				// AuditConditionCommentEventType, i=2829, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> EventId/4170
				//	HasProperty/46 -> Comment/11851
				//	HasSubtype/45 <- AuditConditionEventType/2790
				AddDefaultAddressSpaceNodeObjectType(2829, "AuditConditionCommentEventType", "AuditConditionCommentEventType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  4170,  false),
					(46,  11851,  false),
					(45,  2790,  true),
				});

				// AuditConditionRespondEventType, i=8927, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> SelectedResponse/11852
				//	HasSubtype/45 <- AuditConditionEventType/2790
				AddDefaultAddressSpaceNodeObjectType(8927, "AuditConditionRespondEventType", "AuditConditionRespondEventType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11852,  false),
					(45,  2790,  true),
				});

				// AuditConditionAcknowledgeEventType, i=8944, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> EventId/8945
				//	HasProperty/46 -> Comment/11853
				//	HasSubtype/45 <- AuditConditionEventType/2790
				AddDefaultAddressSpaceNodeObjectType(8944, "AuditConditionAcknowledgeEventType", "AuditConditionAcknowledgeEventType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  8945,  false),
					(46,  11853,  false),
					(45,  2790,  true),
				});

				// AuditConditionConfirmEventType, i=8961, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> EventId/8962
				//	HasProperty/46 -> Comment/11854
				//	HasSubtype/45 <- AuditConditionEventType/2790
				AddDefaultAddressSpaceNodeObjectType(8961, "AuditConditionConfirmEventType", "AuditConditionConfirmEventType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  8962,  false),
					(46,  11854,  false),
					(45,  2790,  true),
				});

				// AuditConditionShelvingEventType, i=11093, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> ShelvingTime/11855
				//	HasSubtype/45 <- AuditConditionEventType/2790
				AddDefaultAddressSpaceNodeObjectType(11093, "AuditConditionShelvingEventType", "AuditConditionShelvingEventType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11855,  false),
					(45,  2790,  true),
				});

				// RefreshStartEventType, i=2787, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- SystemEventType/2130
				AddDefaultAddressSpaceNodeObjectType(2787, "RefreshStartEventType", "RefreshStartEventType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2130,  true),
				});

				// RefreshEndEventType, i=2788, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- SystemEventType/2130
				AddDefaultAddressSpaceNodeObjectType(2788, "RefreshEndEventType", "RefreshEndEventType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2130,  true),
				});

				// RefreshRequiredEventType, i=2789, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasSubtype/45 <- SystemEventType/2130
				AddDefaultAddressSpaceNodeObjectType(2789, "RefreshRequiredEventType", "RefreshRequiredEventType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2130,  true),
				});

				// ProgramStateMachineType, i=2391, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> CurrentState/3830
				//	HasComponent/47 -> LastTransition/3835
				//	HasProperty/46 -> Creatable/2392
				//	HasProperty/46 -> Deletable/2393
				//	HasProperty/46 -> AutoDelete/2394
				//	HasProperty/46 -> RecycleCount/2395
				//	HasProperty/46 -> InstanceCount/2396
				//	HasProperty/46 -> MaxInstanceCount/2397
				//	HasProperty/46 -> MaxRecycleCount/2398
				//	HasComponent/47 -> ProgramDiagnostics/2399
				//	HasComponent/47 -> FinalResultData/3850
				//	HasComponent/47 -> Ready/2400
				//	HasComponent/47 -> Running/2402
				//	HasComponent/47 -> Suspended/2404
				//	HasComponent/47 -> Halted/2406
				//	HasComponent/47 -> HaltedToReady/2408
				//	HasComponent/47 -> ReadyToRunning/2410
				//	HasComponent/47 -> RunningToHalted/2412
				//	HasComponent/47 -> RunningToReady/2414
				//	HasComponent/47 -> RunningToSuspended/2416
				//	HasComponent/47 -> SuspendedToRunning/2418
				//	HasComponent/47 -> SuspendedToHalted/2420
				//	HasComponent/47 -> SuspendedToReady/2422
				//	HasComponent/47 -> ReadyToHalted/2424
				//	HasComponent/47 -> Start/2426
				//	HasComponent/47 -> Suspend/2427
				//	HasComponent/47 -> Resume/2428
				//	HasComponent/47 -> Halt/2429
				//	HasComponent/47 -> Reset/2430
				//	HasSubtype/45 <- FiniteStateMachineType/2771
				AddDefaultAddressSpaceNodeObjectType(2391, "ProgramStateMachineType", "ProgramStateMachineType", "A state machine for a program.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3830,  false),
					(47,  3835,  false),
					(46,  2392,  false),
					(46,  2393,  false),
					(46,  2394,  false),
					(46,  2395,  false),
					(46,  2396,  false),
					(46,  2397,  false),
					(46,  2398,  false),
					(47,  2399,  false),
					(47,  3850,  false),
					(47,  2400,  false),
					(47,  2402,  false),
					(47,  2404,  false),
					(47,  2406,  false),
					(47,  2408,  false),
					(47,  2410,  false),
					(47,  2412,  false),
					(47,  2414,  false),
					(47,  2416,  false),
					(47,  2418,  false),
					(47,  2420,  false),
					(47,  2422,  false),
					(47,  2424,  false),
					(47,  2426,  false),
					(47,  2427,  false),
					(47,  2428,  false),
					(47,  2429,  false),
					(47,  2430,  false),
					(45,  2771,  true),
				});

				// ProgramTransitionEventType, i=2378, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> IntermediateResult/2379
				//	HasSubtype/45 <- TransitionEventType/2311
				AddDefaultAddressSpaceNodeObjectType(2378, "ProgramTransitionEventType", "ProgramTransitionEventType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2379,  false),
					(45,  2311,  true),
				});

				// AuditProgramTransitionEventType, i=11856, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> TransitionNumber/11875
				//	HasSubtype/45 <- AuditUpdateStateEventType/2315
				AddDefaultAddressSpaceNodeObjectType(11856, "AuditProgramTransitionEventType", "AuditProgramTransitionEventType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11875,  false),
					(45,  2315,  true),
				});

				// ProgramTransitionAuditEventType, i=3806, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> Transition/3825
				//	HasSubtype/45 <- AuditUpdateStateEventType/2315
				AddDefaultAddressSpaceNodeObjectType(3806, "ProgramTransitionAuditEventType", "ProgramTransitionAuditEventType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3825,  false),
					(45,  2315,  true),
				});

				// HistoricalDataConfigurationType, i=2318, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> AggregateConfiguration/3059
				//	HasComponent/47 -> AggregateFunctions/11876
				//	HasProperty/46 -> Stepped/2323
				//	HasProperty/46 -> Definition/2324
				//	HasProperty/46 -> MaxTimeInterval/2325
				//	HasProperty/46 -> MinTimeInterval/2326
				//	HasProperty/46 -> ExceptionDeviation/2327
				//	HasProperty/46 -> ExceptionDeviationFormat/2328
				//	HasProperty/46 -> StartOfArchive/11499
				//	HasProperty/46 -> StartOfOnlineArchive/11500
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(2318, "HistoricalDataConfigurationType", "HistoricalDataConfigurationType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3059,  false),
					(47,  11876,  false),
					(46,  2323,  false),
					(46,  2324,  false),
					(46,  2325,  false),
					(46,  2326,  false),
					(46,  2327,  false),
					(46,  2328,  false),
					(46,  11499,  false),
					(46,  11500,  false),
					(45,  58,  true),
				});

				// HistoryServerCapabilitiesType, i=2330, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> AccessHistoryDataCapability/2331
				//	HasProperty/46 -> AccessHistoryEventsCapability/2332
				//	HasProperty/46 -> MaxReturnDataValues/11268
				//	HasProperty/46 -> MaxReturnEventValues/11269
				//	HasProperty/46 -> InsertDataCapability/2334
				//	HasProperty/46 -> ReplaceDataCapability/2335
				//	HasProperty/46 -> UpdateDataCapability/2336
				//	HasProperty/46 -> DeleteRawCapability/2337
				//	HasProperty/46 -> DeleteAtTimeCapability/2338
				//	HasProperty/46 -> InsertEventCapability/11278
				//	HasProperty/46 -> ReplaceEventCapability/11279
				//	HasProperty/46 -> UpdateEventCapability/11280
				//	HasProperty/46 -> DeleteEventCapability/11501
				//	HasProperty/46 -> InsertAnnotationCapability/11270
				//	HasComponent/47 -> AggregateFunctions/11172
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(2330, "HistoryServerCapabilitiesType", "HistoryServerCapabilitiesType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2331,  false),
					(46,  2332,  false),
					(46,  11268,  false),
					(46,  11269,  false),
					(46,  2334,  false),
					(46,  2335,  false),
					(46,  2336,  false),
					(46,  2337,  false),
					(46,  2338,  false),
					(46,  11278,  false),
					(46,  11279,  false),
					(46,  11280,  false),
					(46,  11501,  false),
					(46,  11270,  false),
					(47,  11172,  false),
					(45,  58,  true),
				});

				// AuditHistoryEventUpdateEventType, i=2999, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> UpdatedNode/3025
				//	HasProperty/46 -> PerformInsertReplace/3028
				//	HasProperty/46 -> Filter/3003
				//	HasProperty/46 -> NewValues/3029
				//	HasProperty/46 -> OldValues/3030
				//	HasSubtype/45 <- AuditHistoryUpdateEventType/2104
				AddDefaultAddressSpaceNodeObjectType(2999, "AuditHistoryEventUpdateEventType", "AuditHistoryEventUpdateEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3025,  false),
					(46,  3028,  false),
					(46,  3003,  false),
					(46,  3029,  false),
					(46,  3030,  false),
					(45,  2104,  true),
				});

				// AuditHistoryValueUpdateEventType, i=3006, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> UpdatedNode/3026
				//	HasProperty/46 -> PerformInsertReplace/3031
				//	HasProperty/46 -> NewValues/3032
				//	HasProperty/46 -> OldValues/3033
				//	HasSubtype/45 <- AuditHistoryUpdateEventType/2104
				AddDefaultAddressSpaceNodeObjectType(3006, "AuditHistoryValueUpdateEventType", "AuditHistoryValueUpdateEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3026,  false),
					(46,  3031,  false),
					(46,  3032,  false),
					(46,  3033,  false),
					(45,  2104,  true),
				});

				// AuditHistoryDeleteEventType, i=3012, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> UpdatedNode/3027
				//	HasSubtype/45 <- AuditHistoryUpdateEventType/2104
				//	HasSubtype/45 -> AuditHistoryRawModifyDeleteEventType/3014
				//	HasSubtype/45 -> AuditHistoryAtTimeDeleteEventType/3019
				//	HasSubtype/45 -> AuditHistoryEventDeleteEventType/3022
				AddDefaultAddressSpaceNodeObjectType(3012, "AuditHistoryDeleteEventType", "AuditHistoryDeleteEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3027,  false),
					(45,  2104,  true),
					(45,  3014,  false),
					(45,  3019,  false),
					(45,  3022,  false),
				});

				// AuditHistoryRawModifyDeleteEventType, i=3014, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> IsDeleteModified/3015
				//	HasProperty/46 -> StartTime/3016
				//	HasProperty/46 -> EndTime/3017
				//	HasProperty/46 -> OldValues/3034
				//	HasSubtype/45 <- AuditHistoryDeleteEventType/3012
				AddDefaultAddressSpaceNodeObjectType(3014, "AuditHistoryRawModifyDeleteEventType", "AuditHistoryRawModifyDeleteEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3015,  false),
					(46,  3016,  false),
					(46,  3017,  false),
					(46,  3034,  false),
					(45,  3012,  true),
				});

				// AuditHistoryAtTimeDeleteEventType, i=3019, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> ReqTimes/3020
				//	HasProperty/46 -> OldValues/3021
				//	HasSubtype/45 <- AuditHistoryDeleteEventType/3012
				AddDefaultAddressSpaceNodeObjectType(3019, "AuditHistoryAtTimeDeleteEventType", "AuditHistoryAtTimeDeleteEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3020,  false),
					(46,  3021,  false),
					(45,  3012,  true),
				});

				// AuditHistoryEventDeleteEventType, i=3022, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> EventIds/3023
				//	HasProperty/46 -> OldValues/3024
				//	HasSubtype/45 <- AuditHistoryDeleteEventType/3012
				AddDefaultAddressSpaceNodeObjectType(3022, "AuditHistoryEventDeleteEventType", "AuditHistoryEventDeleteEventType", "", 0, 0, true, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3023,  false),
					(46,  3024,  false),
					(45,  3012,  true),
				});

				// AggregateConfigurationType, i=11187, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasProperty/46 -> TreatUncertainAsBad/11188
				//	HasProperty/46 -> PercentDataBad/11189
				//	HasProperty/46 -> PercentDataGood/11190
				//	HasProperty/46 -> UseSlopedExtrapolation/11191
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(11187, "AggregateConfigurationType", "AggregateConfigurationType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11188,  false),
					(46,  11189,  false),
					(46,  11190,  false),
					(46,  11191,  false),
					(45,  58,  true),
				});

				// LockType, i=8921, TypeGenerator.AddressSpaceGenerator+NodeObjectType
				//	HasComponent/47 -> Lock/8922
				//	HasComponent/47 -> Unlock/8923
				//	HasSubtype/45 <- BaseObjectType/58
				AddDefaultAddressSpaceNodeObjectType(8921, "LockType", "LockType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  8922,  false),
					(47,  8923,  false),
					(45,  58,  true),
				});

				// Default Binary, i=3062, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> BaseObjectType/58
				AddDefaultAddressSpaceNodeObject(3062, "Default Binary", "Default Binary", "The default binary encoding for a data type.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  58,  false),
				});

				// Default XML, i=3063, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> BaseObjectType/58
				AddDefaultAddressSpaceNodeObject(3063, "Default XML", "Default XML", "The default XML encoding for a data type.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  58,  false),
				});

				// Mandatory, i=78, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> NamingRule/112
				//	HasTypeDefinition/40 -> ModellingRuleType/77
				AddDefaultAddressSpaceNodeObject(78, "Mandatory", "Mandatory", "Specifies that an instance with the attributes and references of the instance declaration must appear when a type is instantiated.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  112,  false),
					(40,  77,  false),
				});

				// Optional, i=80, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> NamingRule/113
				//	HasTypeDefinition/40 -> ModellingRuleType/77
				AddDefaultAddressSpaceNodeObject(80, "Optional", "Optional", "Specifies that an instance with the attributes and references of the instance declaration may appear when a type is instantiated.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  113,  false),
					(40,  77,  false),
				});

				// ExposesItsArray, i=83, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> NamingRule/114
				//	HasTypeDefinition/40 -> ModellingRuleType/77
				AddDefaultAddressSpaceNodeObject(83, "ExposesItsArray", "ExposesItsArray", "Specifies that an instance appears for each element of the containing array variable.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  114,  false),
					(40,  77,  false),
				});

				// MandatoryShared, i=79, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> NamingRule/116
				//	HasTypeDefinition/40 -> ModellingRuleType/77
				AddDefaultAddressSpaceNodeObject(79, "MandatoryShared", "MandatoryShared", "Specifies that a reference to a shared instance must appear in when a type is instantiated.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  116,  false),
					(40,  77,  false),
				});

				// OptionalPlaceholder, i=11508, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> NamingRule/11509
				//	HasTypeDefinition/40 -> ModellingRuleType/77
				AddDefaultAddressSpaceNodeObject(11508, "OptionalPlaceholder", "OptionalPlaceholder", "Specifies that zero or more instances with the attributes and references of the instance declaration may appear when a type is instantiated.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11509,  false),
					(40,  77,  false),
				});

				// MandatoryPlaceholder, i=11510, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> NamingRule/11511
				//	HasTypeDefinition/40 -> ModellingRuleType/77
				AddDefaultAddressSpaceNodeObject(11510, "MandatoryPlaceholder", "MandatoryPlaceholder", "Specifies that one or more instances with the attributes and references of the instance declaration must appear when a type is instantiated.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11511,  false),
					(40,  77,  false),
				});

				// Root, i=84, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> FolderType/61
				//	Organizes/35 -> Objects/85
				//	Organizes/35 -> Types/86
				//	Organizes/35 -> Views/87
				AddDefaultAddressSpaceNodeObject(84, "Root", "Root", "The root of the server address space.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  61,  false),
					(35,  85,  false),
					(35,  86,  false),
					(35,  87,  false),
				});

				// Objects, i=85, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	Organizes/35 <- Root/84
				//	HasTypeDefinition/40 -> FolderType/61
				//	Organizes/35 -> Server/2253
				AddDefaultAddressSpaceNodeObject(85, "Objects", "Objects", "The browse entry point when looking for objects in the server address space.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(35,  84,  true),
					(40,  61,  false),
					(35,  2253,  false),
				});

				// Types, i=86, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	Organizes/35 <- Root/84
				//	HasTypeDefinition/40 -> FolderType/61
				//	Organizes/35 -> ObjectTypes/88
				//	Organizes/35 -> VariableTypes/89
				//	Organizes/35 -> DataTypes/90
				//	Organizes/35 -> ReferenceTypes/91
				//	Organizes/35 -> EventTypes/3048
				AddDefaultAddressSpaceNodeObject(86, "Types", "Types", "The browse entry point when looking for types in the server address space.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(35,  84,  true),
					(40,  61,  false),
					(35,  88,  false),
					(35,  89,  false),
					(35,  90,  false),
					(35,  91,  false),
					(35,  3048,  false),
				});

				// Views, i=87, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	Organizes/35 <- Root/84
				//	HasTypeDefinition/40 -> FolderType/61
				AddDefaultAddressSpaceNodeObject(87, "Views", "Views", "The browse entry point when looking for views in the server address space.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(35,  84,  true),
					(40,  61,  false),
				});

				// ObjectTypes, i=88, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	Organizes/35 <- Types/86
				//	Organizes/35 -> BaseObjectType/58
				//	HasTypeDefinition/40 -> FolderType/61
				AddDefaultAddressSpaceNodeObject(88, "ObjectTypes", "ObjectTypes", "The browse entry point when looking for object types in the server address space.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(35,  86,  true),
					(35,  58,  false),
					(40,  61,  false),
				});

			}
			private void Part4()
			{
				// VariableTypes, i=89, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	Organizes/35 <- Types/86
				//	Organizes/35 -> BaseVariableType/62
				//	HasTypeDefinition/40 -> FolderType/61
				AddDefaultAddressSpaceNodeObject(89, "VariableTypes", "VariableTypes", "The browse entry point when looking for variable types in the server address space.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(35,  86,  true),
					(35,  62,  false),
					(40,  61,  false),
				});

				// DataTypes, i=90, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	Organizes/35 <- Types/86
				//	Organizes/35 -> BaseDataType/24
				//	HasTypeDefinition/40 -> FolderType/61
				//	Organizes/35 -> XML Schema/92
				//	Organizes/35 -> OPC Binary/93
				AddDefaultAddressSpaceNodeObject(90, "DataTypes", "DataTypes", "The browse entry point when looking for data types in the server address space.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(35,  86,  true),
					(35,  24,  false),
					(40,  61,  false),
					(35,  92,  false),
					(35,  93,  false),
				});

				// ReferenceTypes, i=91, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	Organizes/35 <- Types/86
				//	Organizes/35 -> References/31
				//	HasTypeDefinition/40 -> FolderType/61
				AddDefaultAddressSpaceNodeObject(91, "ReferenceTypes", "ReferenceTypes", "The browse entry point when looking for reference types in the server address space.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(35,  86,  true),
					(35,  31,  false),
					(40,  61,  false),
				});

				// XML Schema, i=92, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	Organizes/35 <- DataTypes/90
				//	HasTypeDefinition/40 -> DataTypeSystemType/75
				//	HasComponent/47 -> Opc.Ua/8252
				AddDefaultAddressSpaceNodeObject(92, "XML Schema", "XML Schema", "A type system which uses XML schema to describe the encoding of data types.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(35,  90,  true),
					(40,  75,  false),
					(47,  8252,  false),
				});

				// OPC Binary, i=93, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	Organizes/35 <- DataTypes/90
				//	HasTypeDefinition/40 -> DataTypeSystemType/75
				//	HasComponent/47 -> Opc.Ua/7617
				AddDefaultAddressSpaceNodeObject(93, "OPC Binary", "OPC Binary", "A type system which uses OPC binary schema to describe the encoding of data types.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(35,  90,  true),
					(40,  75,  false),
					(47,  7617,  false),
				});

				// ServerCapabilities, i=2009, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> ServerProfileArray/3086
				//	HasProperty/46 -> LocaleIdArray/3087
				//	HasProperty/46 -> MinSupportedSampleRate/3088
				//	HasProperty/46 -> MaxBrowseContinuationPoints/3089
				//	HasProperty/46 -> MaxQueryContinuationPoints/3090
				//	HasProperty/46 -> MaxHistoryContinuationPoints/3091
				//	HasProperty/46 -> SoftwareCertificates/3092
				//	HasComponent/47 -> ModellingRules/3093
				//	HasComponent/47 -> AggregateFunctions/3094
				//	HasTypeDefinition/40 -> ServerCapabilitiesType/2013
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerType/2004
				AddDefaultAddressSpaceNodeObject(2009, "ServerCapabilities", "ServerCapabilities", "Describes capabilities supported by the server.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3086,  false),
					(46,  3087,  false),
					(46,  3088,  false),
					(46,  3089,  false),
					(46,  3090,  false),
					(46,  3091,  false),
					(46,  3092,  false),
					(47,  3093,  false),
					(47,  3094,  false),
					(40,  2013,  false),
					(37,  78,  false),
					(47,  2004,  true),
				});

				// ModellingRules, i=3093, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> FolderType/61
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerCapabilities/2009
				AddDefaultAddressSpaceNodeObject(3093, "ModellingRules", "ModellingRules", "A folder for the modelling rules supported by the server.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  61,  false),
					(37,  78,  false),
					(47,  2009,  true),
				});

				// AggregateFunctions, i=3094, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> FolderType/61
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerCapabilities/2009
				AddDefaultAddressSpaceNodeObject(3094, "AggregateFunctions", "AggregateFunctions", "A folder for the real time aggregates supported by the server.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  61,  false),
					(37,  78,  false),
					(47,  2009,  true),
				});

				// ServerDiagnostics, i=2010, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasComponent/47 -> ServerDiagnosticsSummary/3095
				//	HasComponent/47 -> SubscriptionDiagnosticsArray/3110
				//	HasComponent/47 -> SessionsDiagnosticsSummary/3111
				//	HasProperty/46 -> EnabledFlag/3114
				//	HasTypeDefinition/40 -> ServerDiagnosticsType/2020
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerType/2004
				AddDefaultAddressSpaceNodeObject(2010, "ServerDiagnostics", "ServerDiagnostics", "Reports diagnostics about the server.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3095,  false),
					(47,  3110,  false),
					(47,  3111,  false),
					(46,  3114,  false),
					(40,  2020,  false),
					(37,  78,  false),
					(47,  2004,  true),
				});

				// SessionsDiagnosticsSummary, i=3111, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasComponent/47 -> SessionDiagnosticsArray/3112
				//	HasComponent/47 -> SessionSecurityDiagnosticsArray/3113
				//	HasTypeDefinition/40 -> SessionsDiagnosticsSummaryType/2026
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnostics/2010
				AddDefaultAddressSpaceNodeObject(3111, "SessionsDiagnosticsSummary", "SessionsDiagnosticsSummary", "A summary of session level diagnostics.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3112,  false),
					(47,  3113,  false),
					(40,  2026,  false),
					(37,  78,  false),
					(47,  2010,  true),
				});

				// VendorServerInfo, i=2011, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> VendorServerInfoType/2033
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerType/2004
				AddDefaultAddressSpaceNodeObject(2011, "VendorServerInfo", "VendorServerInfo", "Server information provided by the vendor.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2033,  false),
					(37,  78,  false),
					(47,  2004,  true),
				});

				// ServerRedundancy, i=2012, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> RedundancySupport/3115
				//	HasTypeDefinition/40 -> ServerRedundancyType/2034
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerType/2004
				AddDefaultAddressSpaceNodeObject(2012, "ServerRedundancy", "ServerRedundancy", "Describes the redundancy capabilities of the server.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3115,  false),
					(40,  2034,  false),
					(37,  78,  false),
					(47,  2004,  true),
				});

				// Namespaces, i=11527, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> NamespacesType/11645
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- ServerType/2004
				AddDefaultAddressSpaceNodeObject(11527, "Namespaces", "Namespaces", "Describes the namespaces supported by the server.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  11645,  false),
					(37,  80,  false),
					(47,  2004,  true),
				});

				// OperationLimits, i=11551, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> OperationLimitsType/11564
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- ServerCapabilitiesType/2013
				AddDefaultAddressSpaceNodeObject(11551, "OperationLimits", "OperationLimits", "Defines the limits supported by the server for different operations.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  11564,  false),
					(37,  80,  false),
					(47,  2013,  true),
				});

				// ModellingRules, i=2019, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> FolderType/61
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerCapabilitiesType/2013
				AddDefaultAddressSpaceNodeObject(2019, "ModellingRules", "ModellingRules", "A folder for the modelling rules supported by the server.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  61,  false),
					(37,  78,  false),
					(47,  2013,  true),
				});

				// AggregateFunctions, i=2754, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> FolderType/61
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerCapabilitiesType/2013
				AddDefaultAddressSpaceNodeObject(2754, "AggregateFunctions", "AggregateFunctions", "A folder for the real time aggregates supported by the server.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  61,  false),
					(37,  78,  false),
					(47,  2013,  true),
				});

				// SessionsDiagnosticsSummary, i=2744, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasComponent/47 -> SessionDiagnosticsArray/3129
				//	HasComponent/47 -> SessionSecurityDiagnosticsArray/3130
				//	HasTypeDefinition/40 -> SessionsDiagnosticsSummaryType/2026
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsType/2020
				AddDefaultAddressSpaceNodeObject(2744, "SessionsDiagnosticsSummary", "SessionsDiagnosticsSummary", "A summary of session level diagnostics.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3129,  false),
					(47,  3130,  false),
					(40,  2026,  false),
					(37,  78,  false),
					(47,  2020,  true),
				});

				// <SessionPlaceholder>, i=12097, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasComponent/47 -> SessionDiagnostics/12098
				//	HasComponent/47 -> SessionSecurityDiagnostics/12142
				//	HasComponent/47 -> SubscriptionDiagnosticsArray/12152
				//	HasTypeDefinition/40 -> SessionDiagnosticsObjectType/2029
				//	HasModellingRule/37 -> OptionalPlaceholder/11508
				//	HasComponent/47 <- SessionsDiagnosticsSummaryType/2026
				AddDefaultAddressSpaceNodeObject(12097, "<SessionPlaceholder>", "<SessionPlaceholder>", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  12098,  false),
					(47,  12142,  false),
					(47,  12152,  false),
					(40,  2029,  false),
					(37,  11508,  false),
					(47,  2026,  true),
				});

				// NamespaceFile, i=11624, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> Size/11625
				//	HasProperty/46 -> Writeable/11626
				//	HasProperty/46 -> UserWriteable/11627
				//	HasProperty/46 -> OpenCount/11628
				//	HasComponent/47 -> Open/11629
				//	HasComponent/47 -> Close/11632
				//	HasComponent/47 -> Read/11634
				//	HasComponent/47 -> Write/11637
				//	HasComponent/47 -> GetPosition/11639
				//	HasComponent/47 -> SetPosition/11642
				//	HasTypeDefinition/40 -> AddressSpaceFileType/11595
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- NamespaceMetadataType/11616
				AddDefaultAddressSpaceNodeObject(11624, "NamespaceFile", "NamespaceFile", "A file containing the nodes of the namespace.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11625,  false),
					(46,  11626,  false),
					(46,  11627,  false),
					(46,  11628,  false),
					(47,  11629,  false),
					(47,  11632,  false),
					(47,  11634,  false),
					(47,  11637,  false),
					(47,  11639,  false),
					(47,  11642,  false),
					(40,  11595,  false),
					(37,  80,  false),
					(47,  11616,  true),
				});

				// <NamespaceIdentifier>, i=11646, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> NamespaceUri/11647
				//	HasProperty/46 -> NamespaceVersion/11648
				//	HasProperty/46 -> NamespacePublicationDate/11649
				//	HasProperty/46 -> IsNamespaceSubset/11650
				//	HasProperty/46 -> StaticNodeIdIdentifierTypes/11651
				//	HasProperty/46 -> StaticNumericNodeIdRange/11652
				//	HasProperty/46 -> StaticStringNodeIdPattern/11653
				//	HasTypeDefinition/40 -> NamespaceMetadataType/11616
				//	HasModellingRule/37 -> OptionalPlaceholder/11508
				//	HasComponent/47 <- NamespacesType/11645
				AddDefaultAddressSpaceNodeObject(11646, "<NamespaceIdentifier>", "<NamespaceIdentifier>", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11647,  false),
					(46,  11648,  false),
					(46,  11649,  false),
					(46,  11650,  false),
					(46,  11651,  false),
					(46,  11652,  false),
					(46,  11653,  false),
					(40,  11616,  false),
					(37,  11508,  false),
					(47,  11645,  true),
				});

				// AddressSpaceFile, i=11675, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> Size/11676
				//	HasProperty/46 -> Writeable/11677
				//	HasProperty/46 -> UserWriteable/11678
				//	HasProperty/46 -> OpenCount/11679
				//	HasComponent/47 -> Open/11680
				//	HasComponent/47 -> Close/11683
				//	HasComponent/47 -> Read/11685
				//	HasComponent/47 -> Write/11688
				//	HasComponent/47 -> GetPosition/11690
				//	HasComponent/47 -> SetPosition/11693
				//	HasTypeDefinition/40 -> AddressSpaceFileType/11595
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- NamespacesType/11645
				AddDefaultAddressSpaceNodeObject(11675, "AddressSpaceFile", "AddressSpaceFile", "A file containing the nodes of the namespace.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11676,  false),
					(46,  11677,  false),
					(46,  11678,  false),
					(46,  11679,  false),
					(47,  11680,  false),
					(47,  11683,  false),
					(47,  11685,  false),
					(47,  11688,  false),
					(47,  11690,  false),
					(47,  11693,  false),
					(40,  11595,  false),
					(37,  80,  false),
					(47,  11645,  true),
				});

				// EventTypes, i=3048, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	Organizes/35 <- Types/86
				//	Organizes/35 -> BaseEventType/2041
				//	HasTypeDefinition/40 -> FolderType/61
				AddDefaultAddressSpaceNodeObject(3048, "EventTypes", "EventTypes", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(35,  86,  true),
					(35,  2041,  false),
					(40,  61,  false),
				});

				// Server, i=2253, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> ServerArray/2254
				//	HasProperty/46 -> NamespaceArray/2255
				//	HasComponent/47 -> ServerStatus/2256
				//	HasProperty/46 -> ServiceLevel/2267
				//	HasProperty/46 -> Auditing/2994
				//	HasComponent/47 -> ServerCapabilities/2268
				//	HasComponent/47 -> ServerDiagnostics/2274
				//	HasComponent/47 -> VendorServerInfo/2295
				//	HasComponent/47 -> ServerRedundancy/2296
				//	HasComponent/47 -> Namespaces/11715
				//	HasComponent/47 -> GetMonitoredItems/11492
				//	Organizes/35 <- Objects/85
				//	HasTypeDefinition/40 -> ServerType/2004
				AddDefaultAddressSpaceNodeObject(2253, "Server", "Server", "", 0, 0, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2254,  false),
					(46,  2255,  false),
					(47,  2256,  false),
					(46,  2267,  false),
					(46,  2994,  false),
					(47,  2268,  false),
					(47,  2274,  false),
					(47,  2295,  false),
					(47,  2296,  false),
					(47,  11715,  false),
					(47,  11492,  false),
					(35,  85,  true),
					(40,  2004,  false),
				});

				// ServerCapabilities, i=2268, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> ServerProfileArray/2269
				//	HasProperty/46 -> LocaleIdArray/2271
				//	HasProperty/46 -> MinSupportedSampleRate/2272
				//	HasProperty/46 -> MaxBrowseContinuationPoints/2735
				//	HasProperty/46 -> MaxQueryContinuationPoints/2736
				//	HasProperty/46 -> MaxHistoryContinuationPoints/2737
				//	HasProperty/46 -> SoftwareCertificates/3704
				//	HasProperty/46 -> MaxArrayLength/11702
				//	HasProperty/46 -> MaxStringLength/11703
				//	HasComponent/47 -> OperationLimits/11704
				//	HasComponent/47 -> ModellingRules/2996
				//	HasComponent/47 -> AggregateFunctions/2997
				//	HasTypeDefinition/40 -> ServerCapabilitiesType/2013
				//	HasComponent/47 <- Server/2253
				//	HasComponent/47 -> HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeObject(2268, "ServerCapabilities", "ServerCapabilities", "Describes capabilities supported by the server.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2269,  false),
					(46,  2271,  false),
					(46,  2272,  false),
					(46,  2735,  false),
					(46,  2736,  false),
					(46,  2737,  false),
					(46,  3704,  false),
					(46,  11702,  false),
					(46,  11703,  false),
					(47,  11704,  false),
					(47,  2996,  false),
					(47,  2997,  false),
					(40,  2013,  false),
					(47,  2253,  true),
					(47,  11192,  false),
				});

				// OperationLimits, i=11704, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> MaxNodesPerRead/11705
				//	HasProperty/46 -> MaxNodesPerHistoryReadData/12165
				//	HasProperty/46 -> MaxNodesPerHistoryReadEvents/12166
				//	HasProperty/46 -> MaxNodesPerWrite/11707
				//	HasProperty/46 -> MaxNodesPerHistoryUpdateData/12167
				//	HasProperty/46 -> MaxNodesPerHistoryUpdateEvents/12168
				//	HasProperty/46 -> MaxNodesPerMethodCall/11709
				//	HasProperty/46 -> MaxNodesPerBrowse/11710
				//	HasProperty/46 -> MaxNodesPerRegisterNodes/11711
				//	HasProperty/46 -> MaxNodesPerTranslateBrowsePathsToNodeIds/11712
				//	HasProperty/46 -> MaxNodesPerNodeManagement/11713
				//	HasProperty/46 -> MaxMonitoredItemsPerCall/11714
				//	HasTypeDefinition/40 -> OperationLimitsType/11564
				//	HasComponent/47 <- ServerCapabilities/2268
				AddDefaultAddressSpaceNodeObject(11704, "OperationLimits", "OperationLimits", "Defines the limits supported by the server for different operations.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11705,  false),
					(46,  12165,  false),
					(46,  12166,  false),
					(46,  11707,  false),
					(46,  12167,  false),
					(46,  12168,  false),
					(46,  11709,  false),
					(46,  11710,  false),
					(46,  11711,  false),
					(46,  11712,  false),
					(46,  11713,  false),
					(46,  11714,  false),
					(40,  11564,  false),
					(47,  2268,  true),
				});

				// ModellingRules, i=2996, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> FolderType/61
				//	HasComponent/47 <- ServerCapabilities/2268
				AddDefaultAddressSpaceNodeObject(2996, "ModellingRules", "ModellingRules", "A folder for the modelling rules supported by the server.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  61,  false),
					(47,  2268,  true),
				});

				// AggregateFunctions, i=2997, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> FolderType/61
				//	HasComponent/47 <- ServerCapabilities/2268
				AddDefaultAddressSpaceNodeObject(2997, "AggregateFunctions", "AggregateFunctions", "A folder for the real time aggregates supported by the server.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  61,  false),
					(47,  2268,  true),
				});

				// ServerDiagnostics, i=2274, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasComponent/47 -> ServerDiagnosticsSummary/2275
				//	HasComponent/47 -> SamplingIntervalDiagnosticsArray/2289
				//	HasComponent/47 -> SubscriptionDiagnosticsArray/2290
				//	HasComponent/47 -> SessionsDiagnosticsSummary/3706
				//	HasProperty/46 -> EnabledFlag/2294
				//	HasTypeDefinition/40 -> ServerDiagnosticsType/2020
				//	HasComponent/47 <- Server/2253
				AddDefaultAddressSpaceNodeObject(2274, "ServerDiagnostics", "ServerDiagnostics", "Reports diagnostics about the server.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2275,  false),
					(47,  2289,  false),
					(47,  2290,  false),
					(47,  3706,  false),
					(46,  2294,  false),
					(40,  2020,  false),
					(47,  2253,  true),
				});

				// SessionsDiagnosticsSummary, i=3706, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasComponent/47 -> SessionDiagnosticsArray/3707
				//	HasComponent/47 -> SessionSecurityDiagnosticsArray/3708
				//	HasTypeDefinition/40 -> SessionsDiagnosticsSummaryType/2026
				//	HasComponent/47 <- ServerDiagnostics/2274
				AddDefaultAddressSpaceNodeObject(3706, "SessionsDiagnosticsSummary", "SessionsDiagnosticsSummary", "A summary of session level diagnostics.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3707,  false),
					(47,  3708,  false),
					(40,  2026,  false),
					(47,  2274,  true),
				});

				// VendorServerInfo, i=2295, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> VendorServerInfoType/2033
				//	HasComponent/47 <- Server/2253
				AddDefaultAddressSpaceNodeObject(2295, "VendorServerInfo", "VendorServerInfo", "Server information provided by the vendor.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2033,  false),
					(47,  2253,  true),
				});

				// ServerRedundancy, i=2296, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> RedundancySupport/3709
				//	HasProperty/46 -> CurrentServerId/11312
				//	HasProperty/46 -> RedundantServerArray/11313
				//	HasProperty/46 -> ServerUriArray/11314
				//	HasTypeDefinition/40 -> ServerRedundancyType/2034
				//	HasComponent/47 <- Server/2253
				AddDefaultAddressSpaceNodeObject(2296, "ServerRedundancy", "ServerRedundancy", "Describes the redundancy capabilities of the server.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3709,  false),
					(46,  11312,  false),
					(46,  11313,  false),
					(46,  11314,  false),
					(40,  2034,  false),
					(47,  2253,  true),
				});

				// Namespaces, i=11715, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> NamespacesType/11645
				//	HasComponent/47 <- Server/2253
				AddDefaultAddressSpaceNodeObject(11715, "Namespaces", "Namespaces", "Describes the namespaces supported by the server.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  11645,  false),
					(47,  2253,  true),
				});

				// HistoryServerCapabilities, i=11192, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> AccessHistoryDataCapability/11193
				//	HasProperty/46 -> AccessHistoryEventsCapability/11242
				//	HasProperty/46 -> MaxReturnDataValues/11273
				//	HasProperty/46 -> MaxReturnEventValues/11274
				//	HasProperty/46 -> InsertDataCapability/11196
				//	HasProperty/46 -> ReplaceDataCapability/11197
				//	HasProperty/46 -> UpdateDataCapability/11198
				//	HasProperty/46 -> DeleteRawCapability/11199
				//	HasProperty/46 -> DeleteAtTimeCapability/11200
				//	HasProperty/46 -> InsertEventCapability/11281
				//	HasProperty/46 -> ReplaceEventCapability/11282
				//	HasProperty/46 -> UpdateEventCapability/11283
				//	HasProperty/46 -> DeleteEventCapability/11502
				//	HasProperty/46 -> InsertAnnotationCapability/11275
				//	HasComponent/47 -> AggregateFunctions/11201
				//	HasComponent/47 <- ServerCapabilities/2268
				//	HasTypeDefinition/40 -> HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeObject(11192, "HistoryServerCapabilities", "HistoryServerCapabilities", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11193,  false),
					(46,  11242,  false),
					(46,  11273,  false),
					(46,  11274,  false),
					(46,  11196,  false),
					(46,  11197,  false),
					(46,  11198,  false),
					(46,  11199,  false),
					(46,  11200,  false),
					(46,  11281,  false),
					(46,  11282,  false),
					(46,  11283,  false),
					(46,  11502,  false),
					(46,  11275,  false),
					(47,  11201,  false),
					(47,  2268,  true),
					(40,  2330,  false),
				});

				// AggregateFunctions, i=11201, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> FolderType/61
				//	HasComponent/47 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeObject(11201, "AggregateFunctions", "AggregateFunctions", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  61,  false),
					(47,  11192,  true),
				});

				// ShelvingState, i=9178, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasComponent/47 -> CurrentState/9179
				//	HasComponent/47 -> LastTransition/9184
				//	HasProperty/46 -> UnshelveTime/9189
				//	HasComponent/47 -> Unshelve/9211
				//	HasComponent/47 -> OneShotShelve/9212
				//	HasComponent/47 -> TimedShelve/9213
				//	i=9004/9004 <- EnabledState/9118
				//	HasTypeDefinition/40 -> ShelvedStateMachineType/2929
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- AlarmConditionType/2915
				AddDefaultAddressSpaceNodeObject(9178, "ShelvingState", "ShelvingState", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  9179,  false),
					(47,  9184,  false),
					(46,  9189,  false),
					(47,  9211,  false),
					(47,  9212,  false),
					(47,  9213,  false),
					(9004,  9118,  true),
					(40,  2929,  false),
					(37,  80,  false),
					(47,  2915,  true),
				});

				// Unshelved, i=2930, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> StateNumber/6098
				//	i=51/51 <- UnshelvedToTimedShelved/2935
				//	i=51/51 <- UnshelvedToOneShotShelved/2936
				//	i=52/52 <- TimedShelvedToUnshelved/2940
				//	i=52/52 <- OneShotShelvedToUnshelved/2943
				//	HasTypeDefinition/40 -> StateType/2307
				//	HasComponent/47 <- ShelvedStateMachineType/2929
				AddDefaultAddressSpaceNodeObject(2930, "Unshelved", "Unshelved", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  6098,  false),
					(51,  2935,  true),
					(51,  2936,  true),
					(52,  2940,  true),
					(52,  2943,  true),
					(40,  2307,  false),
					(47,  2929,  true),
				});

				// TimedShelved, i=2932, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> StateNumber/6100
				//	i=52/52 <- UnshelvedToTimedShelved/2935
				//	i=51/51 <- TimedShelvedToUnshelved/2940
				//	i=51/51 <- TimedShelvedToOneShotShelved/2942
				//	i=52/52 <- OneShotShelvedToTimedShelved/2945
				//	HasTypeDefinition/40 -> StateType/2307
				//	HasComponent/47 <- ShelvedStateMachineType/2929
				AddDefaultAddressSpaceNodeObject(2932, "TimedShelved", "TimedShelved", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  6100,  false),
					(52,  2935,  true),
					(51,  2940,  true),
					(51,  2942,  true),
					(52,  2945,  true),
					(40,  2307,  false),
					(47,  2929,  true),
				});

				// OneShotShelved, i=2933, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> StateNumber/6101
				//	i=52/52 <- UnshelvedToOneShotShelved/2936
				//	i=52/52 <- TimedShelvedToOneShotShelved/2942
				//	i=51/51 <- OneShotShelvedToUnshelved/2943
				//	i=51/51 <- OneShotShelvedToTimedShelved/2945
				//	HasTypeDefinition/40 -> StateType/2307
				//	HasComponent/47 <- ShelvedStateMachineType/2929
				AddDefaultAddressSpaceNodeObject(2933, "OneShotShelved", "OneShotShelved", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  6101,  false),
					(52,  2936,  true),
					(52,  2942,  true),
					(51,  2943,  true),
					(51,  2945,  true),
					(40,  2307,  false),
					(47,  2929,  true),
				});

				// UnshelvedToTimedShelved, i=2935, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/11322
				//	i=51/51 -> Unshelved/2930
				//	i=52/52 -> TimedShelved/2932
				//	i=54/54 -> AlarmConditionType/2915
				//	i=53/53 -> TimedShelve/2949
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ShelvedStateMachineType/2929
				AddDefaultAddressSpaceNodeObject(2935, "UnshelvedToTimedShelved", "UnshelvedToTimedShelved", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11322,  false),
					(51,  2930,  false),
					(52,  2932,  false),
					(54,  2915,  false),
					(53,  2949,  false),
					(40,  2310,  false),
					(47,  2929,  true),
				});

				// UnshelvedToOneShotShelved, i=2936, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/11323
				//	i=51/51 -> Unshelved/2930
				//	i=52/52 -> OneShotShelved/2933
				//	i=54/54 -> AlarmConditionType/2915
				//	i=53/53 -> OneShotShelve/2948
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ShelvedStateMachineType/2929
				AddDefaultAddressSpaceNodeObject(2936, "UnshelvedToOneShotShelved", "UnshelvedToOneShotShelved", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11323,  false),
					(51,  2930,  false),
					(52,  2933,  false),
					(54,  2915,  false),
					(53,  2948,  false),
					(40,  2310,  false),
					(47,  2929,  true),
				});

				// TimedShelvedToUnshelved, i=2940, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/11324
				//	i=51/51 -> TimedShelved/2932
				//	i=52/52 -> Unshelved/2930
				//	i=54/54 -> AlarmConditionType/2915
				//	i=53/53 -> Unshelve/2947
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ShelvedStateMachineType/2929
				AddDefaultAddressSpaceNodeObject(2940, "TimedShelvedToUnshelved", "TimedShelvedToUnshelved", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11324,  false),
					(51,  2932,  false),
					(52,  2930,  false),
					(54,  2915,  false),
					(53,  2947,  false),
					(40,  2310,  false),
					(47,  2929,  true),
				});

				// TimedShelvedToOneShotShelved, i=2942, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/11325
				//	i=51/51 -> TimedShelved/2932
				//	i=52/52 -> OneShotShelved/2933
				//	i=54/54 -> AlarmConditionType/2915
				//	i=53/53 -> OneShotShelve/2948
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ShelvedStateMachineType/2929
				AddDefaultAddressSpaceNodeObject(2942, "TimedShelvedToOneShotShelved", "TimedShelvedToOneShotShelved", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11325,  false),
					(51,  2932,  false),
					(52,  2933,  false),
					(54,  2915,  false),
					(53,  2948,  false),
					(40,  2310,  false),
					(47,  2929,  true),
				});

				// OneShotShelvedToUnshelved, i=2943, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/11326
				//	i=51/51 -> OneShotShelved/2933
				//	i=52/52 -> Unshelved/2930
				//	i=54/54 -> AlarmConditionType/2915
				//	i=53/53 -> Unshelve/2947
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ShelvedStateMachineType/2929
				AddDefaultAddressSpaceNodeObject(2943, "OneShotShelvedToUnshelved", "OneShotShelvedToUnshelved", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11326,  false),
					(51,  2933,  false),
					(52,  2930,  false),
					(54,  2915,  false),
					(53,  2947,  false),
					(40,  2310,  false),
					(47,  2929,  true),
				});

				// OneShotShelvedToTimedShelved, i=2945, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/11327
				//	i=51/51 -> OneShotShelved/2933
				//	i=52/52 -> TimedShelved/2932
				//	i=54/54 -> AlarmConditionType/2915
				//	i=53/53 -> TimedShelve/2949
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ShelvedStateMachineType/2929
				AddDefaultAddressSpaceNodeObject(2945, "OneShotShelvedToTimedShelved", "OneShotShelvedToTimedShelved", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11327,  false),
					(51,  2933,  false),
					(52,  2932,  false),
					(54,  2915,  false),
					(53,  2949,  false),
					(40,  2310,  false),
					(47,  2929,  true),
				});

				// HighHigh, i=9329, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> StateNumber/9330
				//	i=51/51 <- HighHighToHigh/9339
				//	i=52/52 <- HighToHighHigh/9340
				//	HasTypeDefinition/40 -> StateType/2307
				//	HasComponent/47 <- ExclusiveLimitStateMachineType/9318
				AddDefaultAddressSpaceNodeObject(9329, "HighHigh", "HighHigh", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9330,  false),
					(51,  9339,  true),
					(52,  9340,  true),
					(40,  2307,  false),
					(47,  9318,  true),
				});

				// High, i=9331, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> StateNumber/9332
				//	i=52/52 <- HighHighToHigh/9339
				//	i=51/51 <- HighToHighHigh/9340
				//	HasTypeDefinition/40 -> StateType/2307
				//	HasComponent/47 <- ExclusiveLimitStateMachineType/9318
				AddDefaultAddressSpaceNodeObject(9331, "High", "High", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9332,  false),
					(52,  9339,  true),
					(51,  9340,  true),
					(40,  2307,  false),
					(47,  9318,  true),
				});

				// Low, i=9333, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> StateNumber/9334
				//	i=52/52 <- LowLowToLow/9337
				//	i=51/51 <- LowToLowLow/9338
				//	HasTypeDefinition/40 -> StateType/2307
				//	HasComponent/47 <- ExclusiveLimitStateMachineType/9318
				AddDefaultAddressSpaceNodeObject(9333, "Low", "Low", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9334,  false),
					(52,  9337,  true),
					(51,  9338,  true),
					(40,  2307,  false),
					(47,  9318,  true),
				});

				// LowLow, i=9335, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> StateNumber/9336
				//	i=51/51 <- LowLowToLow/9337
				//	i=52/52 <- LowToLowLow/9338
				//	HasTypeDefinition/40 -> StateType/2307
				//	HasComponent/47 <- ExclusiveLimitStateMachineType/9318
				AddDefaultAddressSpaceNodeObject(9335, "LowLow", "LowLow", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9336,  false),
					(51,  9337,  true),
					(52,  9338,  true),
					(40,  2307,  false),
					(47,  9318,  true),
				});

				// LowLowToLow, i=9337, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/11340
				//	i=51/51 -> LowLow/9335
				//	i=52/52 -> Low/9333
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ExclusiveLimitStateMachineType/9318
				AddDefaultAddressSpaceNodeObject(9337, "LowLowToLow", "LowLowToLow", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11340,  false),
					(51,  9335,  false),
					(52,  9333,  false),
					(40,  2310,  false),
					(47,  9318,  true),
				});

				// LowToLowLow, i=9338, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/11341
				//	i=51/51 -> Low/9333
				//	i=52/52 -> LowLow/9335
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ExclusiveLimitStateMachineType/9318
				AddDefaultAddressSpaceNodeObject(9338, "LowToLowLow", "LowToLowLow", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11341,  false),
					(51,  9333,  false),
					(52,  9335,  false),
					(40,  2310,  false),
					(47,  9318,  true),
				});

				// HighHighToHigh, i=9339, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/11342
				//	i=51/51 -> HighHigh/9329
				//	i=52/52 -> High/9331
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ExclusiveLimitStateMachineType/9318
				AddDefaultAddressSpaceNodeObject(9339, "HighHighToHigh", "HighHighToHigh", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11342,  false),
					(51,  9329,  false),
					(52,  9331,  false),
					(40,  2310,  false),
					(47,  9318,  true),
				});

				// HighToHighHigh, i=9340, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/11343
				//	i=51/51 -> High/9331
				//	i=52/52 -> HighHigh/9329
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ExclusiveLimitStateMachineType/9318
				AddDefaultAddressSpaceNodeObject(9340, "HighToHighHigh", "HighToHighHigh", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11343,  false),
					(51,  9331,  false),
					(52,  9329,  false),
					(40,  2310,  false),
					(47,  9318,  true),
				});

				// LimitState, i=9455, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasComponent/47 -> CurrentState/9456
				//	HasComponent/47 -> LastTransition/9461
				//	i=9004/9004 <- ActiveState/9398
				//	HasTypeDefinition/40 -> ExclusiveLimitStateMachineType/9318
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ExclusiveLimitAlarmType/9341
				AddDefaultAddressSpaceNodeObject(9455, "LimitState", "LimitState", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  9456,  false),
					(47,  9461,  false),
					(9004,  9398,  true),
					(40,  9318,  false),
					(37,  78,  false),
					(47,  9341,  true),
				});

				// FinalResultData, i=3850, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> BaseObjectType/58
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObject(3850, "FinalResultData", "FinalResultData", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  58,  false),
					(37,  80,  false),
					(47,  2391,  true),
				});

				// Ready, i=2400, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> StateNumber/2401
				//	i=52/52 <- HaltedToReady/2408
				//	i=51/51 <- ReadyToRunning/2410
				//	i=52/52 <- RunningToReady/2414
				//	i=52/52 <- SuspendedToReady/2422
				//	i=51/51 <- ReadyToHalted/2424
				//	HasTypeDefinition/40 -> StateType/2307
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObject(2400, "Ready", "Ready", "The Program is properly initialized and may be started.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2401,  false),
					(52,  2408,  true),
					(51,  2410,  true),
					(52,  2414,  true),
					(52,  2422,  true),
					(51,  2424,  true),
					(40,  2307,  false),
					(47,  2391,  true),
				});

				// Running, i=2402, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> StateNumber/2403
				//	i=52/52 <- ReadyToRunning/2410
				//	i=51/51 <- RunningToHalted/2412
				//	i=51/51 <- RunningToReady/2414
				//	i=51/51 <- RunningToSuspended/2416
				//	i=52/52 <- SuspendedToRunning/2418
				//	HasTypeDefinition/40 -> StateType/2307
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObject(2402, "Running", "Running", "The Program is executing making progress towards completion.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2403,  false),
					(52,  2410,  true),
					(51,  2412,  true),
					(51,  2414,  true),
					(51,  2416,  true),
					(52,  2418,  true),
					(40,  2307,  false),
					(47,  2391,  true),
				});

				// Suspended, i=2404, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> StateNumber/2405
				//	i=52/52 <- RunningToSuspended/2416
				//	i=51/51 <- SuspendedToRunning/2418
				//	i=51/51 <- SuspendedToHalted/2420
				//	i=51/51 <- SuspendedToReady/2422
				//	HasTypeDefinition/40 -> StateType/2307
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObject(2404, "Suspended", "Suspended", "The Program has been stopped prior to reaching a terminal state but may be resumed.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2405,  false),
					(52,  2416,  true),
					(51,  2418,  true),
					(51,  2420,  true),
					(51,  2422,  true),
					(40,  2307,  false),
					(47,  2391,  true),
				});

				// Halted, i=2406, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> StateNumber/2407
				//	i=51/51 <- HaltedToReady/2408
				//	i=52/52 <- RunningToHalted/2412
				//	i=52/52 <- SuspendedToHalted/2420
				//	i=52/52 <- ReadyToHalted/2424
				//	HasTypeDefinition/40 -> StateType/2307
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObject(2406, "Halted", "Halted", "The Program is in a terminal or failed state, and it cannot be started or resumed without being reset.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2407,  false),
					(51,  2408,  true),
					(52,  2412,  true),
					(52,  2420,  true),
					(52,  2424,  true),
					(40,  2307,  false),
					(47,  2391,  true),
				});

				// HaltedToReady, i=2408, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/2409
				//	i=51/51 -> Halted/2406
				//	i=52/52 -> Ready/2400
				//	i=53/53 -> Reset/2430
				//	i=54/54 -> ProgramTransitionEventType/2378
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObject(2408, "HaltedToReady", "HaltedToReady", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2409,  false),
					(51,  2406,  false),
					(52,  2400,  false),
					(53,  2430,  false),
					(54,  2378,  false),
					(40,  2310,  false),
					(47,  2391,  true),
				});

				// ReadyToRunning, i=2410, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/2411
				//	i=51/51 -> Ready/2400
				//	i=52/52 -> Running/2402
				//	i=53/53 -> Start/2426
				//	i=54/54 -> ProgramTransitionEventType/2378
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObject(2410, "ReadyToRunning", "ReadyToRunning", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2411,  false),
					(51,  2400,  false),
					(52,  2402,  false),
					(53,  2426,  false),
					(54,  2378,  false),
					(40,  2310,  false),
					(47,  2391,  true),
				});

				// RunningToHalted, i=2412, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/2413
				//	i=51/51 -> Running/2402
				//	i=52/52 -> Halted/2406
				//	i=53/53 -> Halt/2429
				//	i=54/54 -> ProgramTransitionEventType/2378
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObject(2412, "RunningToHalted", "RunningToHalted", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2413,  false),
					(51,  2402,  false),
					(52,  2406,  false),
					(53,  2429,  false),
					(54,  2378,  false),
					(40,  2310,  false),
					(47,  2391,  true),
				});

				// RunningToReady, i=2414, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/2415
				//	i=51/51 -> Running/2402
				//	i=52/52 -> Ready/2400
				//	i=54/54 -> ProgramTransitionEventType/2378
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObject(2414, "RunningToReady", "RunningToReady", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2415,  false),
					(51,  2402,  false),
					(52,  2400,  false),
					(54,  2378,  false),
					(40,  2310,  false),
					(47,  2391,  true),
				});

			}
			private void Part5()
			{
				// RunningToSuspended, i=2416, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/2417
				//	i=51/51 -> Running/2402
				//	i=52/52 -> Suspended/2404
				//	i=53/53 -> Suspend/2427
				//	i=54/54 -> ProgramTransitionEventType/2378
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObject(2416, "RunningToSuspended", "RunningToSuspended", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2417,  false),
					(51,  2402,  false),
					(52,  2404,  false),
					(53,  2427,  false),
					(54,  2378,  false),
					(40,  2310,  false),
					(47,  2391,  true),
				});

				// SuspendedToRunning, i=2418, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/2419
				//	i=51/51 -> Suspended/2404
				//	i=52/52 -> Running/2402
				//	i=53/53 -> Resume/2428
				//	i=54/54 -> ProgramTransitionEventType/2378
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObject(2418, "SuspendedToRunning", "SuspendedToRunning", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2419,  false),
					(51,  2404,  false),
					(52,  2402,  false),
					(53,  2428,  false),
					(54,  2378,  false),
					(40,  2310,  false),
					(47,  2391,  true),
				});

				// SuspendedToHalted, i=2420, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/2421
				//	i=51/51 -> Suspended/2404
				//	i=52/52 -> Halted/2406
				//	i=53/53 -> Halt/2429
				//	i=54/54 -> ProgramTransitionEventType/2378
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObject(2420, "SuspendedToHalted", "SuspendedToHalted", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2421,  false),
					(51,  2404,  false),
					(52,  2406,  false),
					(53,  2429,  false),
					(54,  2378,  false),
					(40,  2310,  false),
					(47,  2391,  true),
				});

				// SuspendedToReady, i=2422, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/2423
				//	i=51/51 -> Suspended/2404
				//	i=52/52 -> Ready/2400
				//	i=54/54 -> ProgramTransitionEventType/2378
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObject(2422, "SuspendedToReady", "SuspendedToReady", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2423,  false),
					(51,  2404,  false),
					(52,  2400,  false),
					(54,  2378,  false),
					(40,  2310,  false),
					(47,  2391,  true),
				});

				// ReadyToHalted, i=2424, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TransitionNumber/2425
				//	i=51/51 -> Ready/2400
				//	i=52/52 -> Halted/2406
				//	i=53/53 -> Halt/2429
				//	i=54/54 -> ProgramTransitionEventType/2378
				//	HasTypeDefinition/40 -> TransitionType/2310
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeObject(2424, "ReadyToHalted", "ReadyToHalted", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2425,  false),
					(51,  2400,  false),
					(52,  2406,  false),
					(53,  2429,  false),
					(54,  2378,  false),
					(40,  2310,  false),
					(47,  2391,  true),
				});

				// AggregateConfiguration, i=3059, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TreatUncertainAsBad/11168
				//	HasProperty/46 -> PercentDataBad/11169
				//	HasProperty/46 -> PercentDataGood/11170
				//	HasProperty/46 -> UseSlopedExtrapolation/11171
				//	HasTypeDefinition/40 -> AggregateConfigurationType/11187
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- HistoricalDataConfigurationType/2318
				AddDefaultAddressSpaceNodeObject(3059, "AggregateConfiguration", "AggregateConfiguration", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11168,  false),
					(46,  11169,  false),
					(46,  11170,  false),
					(46,  11171,  false),
					(40,  11187,  false),
					(37,  78,  false),
					(47,  2318,  true),
				});

				// AggregateFunctions, i=11876, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> FolderType/61
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- HistoricalDataConfigurationType/2318
				AddDefaultAddressSpaceNodeObject(11876, "AggregateFunctions", "AggregateFunctions", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  61,  false),
					(37,  80,  false),
					(47,  2318,  true),
				});

				// HA Configuration, i=11202, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasComponent/47 -> AggregateConfiguration/11203
				//	HasProperty/46 -> Stepped/11208
				//	HasTypeDefinition/40 -> HistoricalDataConfigurationType/2318
				AddDefaultAddressSpaceNodeObject(11202, "HA Configuration", "HA Configuration", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  11203,  false),
					(46,  11208,  false),
					(40,  2318,  false),
				});

				// AggregateConfiguration, i=11203, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasProperty/46 -> TreatUncertainAsBad/11204
				//	HasProperty/46 -> PercentDataBad/11205
				//	HasProperty/46 -> PercentDataGood/11206
				//	HasProperty/46 -> UseSlopedExtrapolation/11207
				//	HasTypeDefinition/40 -> AggregateConfigurationType/11187
				//	HasComponent/47 <- HA Configuration/11202
				AddDefaultAddressSpaceNodeObject(11203, "AggregateConfiguration", "AggregateConfiguration", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11204,  false),
					(46,  11205,  false),
					(46,  11206,  false),
					(46,  11207,  false),
					(40,  11187,  false),
					(47,  11202,  true),
				});

				// AggregateFunctions, i=11172, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> FolderType/61
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeObject(11172, "AggregateFunctions", "AggregateFunctions", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  61,  false),
					(37,  78,  false),
					(47,  2330,  true),
				});

				// Interpolative, i=2341, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2341, "Interpolative", "Interpolative", "At the beginning of each interval, retrieve the calculated value from the data points on either side of the requested timestamp.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// Average, i=2342, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2342, "Average", "Average", "Retrieve the average value of the data over the interval.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// TimeAverage, i=2343, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2343, "TimeAverage", "TimeAverage", "Retrieve the time weighted average data over the interval using Interpolated Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// TimeAverage2, i=11285, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11285, "TimeAverage2", "TimeAverage2", "Retrieve the time weighted average data over the interval using Simple Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// Total, i=2344, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2344, "Total", "Total", "Retrieve the total (time integral) of the data over the interval using Interpolated Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// Total2, i=11304, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11304, "Total2", "Total2", "Retrieve the total (time integral) of the data over the interval using Simple Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// Minimum, i=2346, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2346, "Minimum", "Minimum", "Retrieve the minimum raw value in the interval with the timestamp of the start of the interval.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// Maximum, i=2347, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2347, "Maximum", "Maximum", "Retrieve the maximum raw value in the interval with the timestamp of the start of the interval.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// MinimumActualTime, i=2348, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2348, "MinimumActualTime", "MinimumActualTime", "Retrieve the minimum value in the interval and the Timestamp of the minimum value.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// MaximumActualTime, i=2349, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2349, "MaximumActualTime", "MaximumActualTime", "Retrieve the maximum value in the interval and the Timestamp of the maximum value.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// Range, i=2350, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2350, "Range", "Range", "Retrieve the difference between the minimum and maximum Value over the interval.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// Minimum2, i=11286, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11286, "Minimum2", "Minimum2", "Retrieve the minimum value in the interval including the Simple Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// Maximum2, i=11287, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11287, "Maximum2", "Maximum2", "Retrieve the maximum value in the interval including the Simple Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// MinimumActualTime2, i=11305, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11305, "MinimumActualTime2", "MinimumActualTime2", "Retrieve the minimum value with the actual timestamp including the Simple Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// MaximumActualTime2, i=11306, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11306, "MaximumActualTime2", "MaximumActualTime2", "Retrieve the maximum value with the actual timestamp including the Simple Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// Range2, i=11288, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11288, "Range2", "Range2", "Retrieve the difference between the Minimum2 and Maximum2 value over the interval.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// AnnotationCount, i=2351, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2351, "AnnotationCount", "AnnotationCount", "Retrieve the number of Annotations in the interval.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// Count, i=2352, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2352, "Count", "Count", "Retrieve the number of raw values over the interval.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// DurationInStateZero, i=11307, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11307, "DurationInStateZero", "DurationInStateZero", "Retrieve the time a Boolean or numeric was in a zero state using Simple Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// DurationInStateNonZero, i=11308, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11308, "DurationInStateNonZero", "DurationInStateNonZero", "Retrieve the time a Boolean or numeric was in a non-zero state using Simple Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// NumberOfTransitions, i=2355, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2355, "NumberOfTransitions", "NumberOfTransitions", "Retrieve the number of changes between zero and non-zero that a Boolean or Numeric value experienced in the interval.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// Start, i=2357, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2357, "Start", "Start", "Retrieve the value at the beginning of the interval using Interpolated Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// End, i=2358, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2358, "End", "End", "Retrieve the value at the end of the interval using Interpolated Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// Delta, i=2359, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2359, "Delta", "Delta", "Retrieve the difference between the Start and End value in the interval.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// StartBound, i=11505, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11505, "StartBound", "StartBound", "Retrieve the value at the beginning of the interval using Simple Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// EndBound, i=11506, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11506, "EndBound", "EndBound", "Retrieve the value at the end of the interval using Simple Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// DeltaBounds, i=11507, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11507, "DeltaBounds", "DeltaBounds", "Retrieve the difference between the StartBound and EndBound value in the interval.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// DurationGood, i=2360, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2360, "DurationGood", "DurationGood", "Retrieve the total duration of time in the interval during which the data is good.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// DurationBad, i=2361, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2361, "DurationBad", "DurationBad", "Retrieve the total duration of time in the interval during which the data is bad.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// PercentGood, i=2362, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2362, "PercentGood", "PercentGood", "Retrieve the percent of data (0 to 100) in the interval which has a good StatusCode.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// PercentBad, i=2363, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2363, "PercentBad", "PercentBad", "Retrieve the percent of data (0 to 100) in the interval which has a bad StatusCode.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// WorstQuality, i=2364, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(2364, "WorstQuality", "WorstQuality", "Retrieve the worst StatusCode of data in the interval.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// WorstQuality2, i=11292, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11292, "WorstQuality2", "WorstQuality2", "Retrieve the worst StatusCode of data in the interval including the Simple Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// StandardDeviationSample, i=11426, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11426, "StandardDeviationSample", "StandardDeviationSample", "Retrieve the standard deviation for the interval for a sample of the population (n-1).", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// StandardDeviationPopulation, i=11427, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11427, "StandardDeviationPopulation", "StandardDeviationPopulation", "Retrieve the standard deviation for the interval for a complete population (n) which includes Simple Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// VarianceSample, i=11428, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11428, "VarianceSample", "VarianceSample", "Retrieve the variance for the interval as calculated by the StandardDeviationSample.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// VariancePopulation, i=11429, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasTypeDefinition/40 -> AggregateFunctionType/2340
				AddDefaultAddressSpaceNodeObject(11429, "VariancePopulation", "VariancePopulation", "Retrieve the variance for the interval as calculated by the StandardDeviationPopulation which includes Simple Bounding Values.", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2340,  false),
				});

				// ServerLock, i=8924, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasComponent/47 -> Lock/8925
				//	HasComponent/47 -> Unlock/8926
				//	HasTypeDefinition/40 -> LockType/8921
				AddDefaultAddressSpaceNodeObject(8924, "ServerLock", "ServerLock", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  8925,  false),
					(47,  8926,  false),
					(40,  8921,  false),
				});

				// Default XML, i=297, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- Argument/296
				//	HasDescription/39 -> Argument/8285
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(297, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  296,  true),
					(39,  8285,  false),
					(40,  76,  false),
				});

				// Default XML, i=7616, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- EnumValueType/7594
				//	HasDescription/39 -> EnumValueType/8291
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(7616, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  7594,  true),
					(39,  8291,  false),
					(40,  76,  false),
				});

				// Default XML, i=8913, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- TimeZoneDataType/8912
				//	HasDescription/39 -> TimeZoneDataType/8918
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(8913, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  8912,  true),
					(39,  8918,  false),
					(40,  76,  false),
				});

				// Default XML, i=309, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ApplicationDescription/308
				//	HasDescription/39 -> ApplicationDescription/8300
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(309, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  308,  true),
					(39,  8300,  false),
					(40,  76,  false),
				});

				// Default XML, i=305, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- UserTokenPolicy/304
				//	HasDescription/39 -> UserTokenPolicy/8297
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(305, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  304,  true),
					(39,  8297,  false),
					(40,  76,  false),
				});

				// Default XML, i=313, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- EndpointDescription/312
				//	HasDescription/39 -> EndpointDescription/8303
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(313, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  312,  true),
					(39,  8303,  false),
					(40,  76,  false),
				});

				// Default XML, i=433, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- RegisteredServer/432
				//	HasDescription/39 -> RegisteredServer/8417
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(433, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  432,  true),
					(39,  8417,  false),
					(40,  76,  false),
				});

				// Default XML, i=345, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SignedSoftwareCertificate/344
				//	HasDescription/39 -> SignedSoftwareCertificate/8333
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(345, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  344,  true),
					(39,  8333,  false),
					(40,  76,  false),
				});

				// Default XML, i=317, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- UserIdentityToken/316
				//	HasDescription/39 -> UserIdentityToken/8306
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(317, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  316,  true),
					(39,  8306,  false),
					(40,  76,  false),
				});

				// Default XML, i=320, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- AnonymousIdentityToken/319
				//	HasDescription/39 -> AnonymousIdentityToken/8309
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(320, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  319,  true),
					(39,  8309,  false),
					(40,  76,  false),
				});

				// Default XML, i=323, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- UserNameIdentityToken/322
				//	HasDescription/39 -> UserNameIdentityToken/8312
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(323, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  322,  true),
					(39,  8312,  false),
					(40,  76,  false),
				});

				// Default XML, i=326, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- X509IdentityToken/325
				//	HasDescription/39 -> X509IdentityToken/8315
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(326, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  325,  true),
					(39,  8315,  false),
					(40,  76,  false),
				});

				// Default XML, i=939, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- IssuedIdentityToken/938
				//	HasDescription/39 -> IssuedIdentityToken/8318
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(939, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  938,  true),
					(39,  8318,  false),
					(40,  76,  false),
				});

				// Default XML, i=377, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- AddNodesItem/376
				//	HasDescription/39 -> AddNodesItem/8363
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(377, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  376,  true),
					(39,  8363,  false),
					(40,  76,  false),
				});

				// Default XML, i=380, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- AddReferencesItem/379
				//	HasDescription/39 -> AddReferencesItem/8366
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(380, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  379,  true),
					(39,  8366,  false),
					(40,  76,  false),
				});

				// Default XML, i=383, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- DeleteNodesItem/382
				//	HasDescription/39 -> DeleteNodesItem/8369
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(383, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  382,  true),
					(39,  8369,  false),
					(40,  76,  false),
				});

				// Default XML, i=386, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- DeleteReferencesItem/385
				//	HasDescription/39 -> DeleteReferencesItem/8372
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(386, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  385,  true),
					(39,  8372,  false),
					(40,  76,  false),
				});

				// Default XML, i=332, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- EndpointConfiguration/331
				//	HasDescription/39 -> EndpointConfiguration/8321
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(332, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  331,  true),
					(39,  8321,  false),
					(40,  76,  false),
				});

				// Default XML, i=336, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SupportedProfile/335
				//	HasDescription/39 -> SupportedProfile/8324
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(336, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  335,  true),
					(39,  8324,  false),
					(40,  76,  false),
				});

				// Default XML, i=342, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SoftwareCertificate/341
				//	HasDescription/39 -> SoftwareCertificate/8330
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(342, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  341,  true),
					(39,  8330,  false),
					(40,  76,  false),
				});

				// Default XML, i=584, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ContentFilterElement/583
				//	HasDescription/39 -> ContentFilterElement/8564
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(584, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  583,  true),
					(39,  8564,  false),
					(40,  76,  false),
				});

				// Default XML, i=587, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ContentFilter/586
				//	HasDescription/39 -> ContentFilter/8567
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(587, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  586,  true),
					(39,  8567,  false),
					(40,  76,  false),
				});

				// Default XML, i=590, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- FilterOperand/589
				//	HasDescription/39 -> FilterOperand/8570
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(590, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  589,  true),
					(39,  8570,  false),
					(40,  76,  false),
				});

				// Default XML, i=593, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ElementOperand/592
				//	HasDescription/39 -> ElementOperand/8573
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(593, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  592,  true),
					(39,  8573,  false),
					(40,  76,  false),
				});

				// Default XML, i=596, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- LiteralOperand/595
				//	HasDescription/39 -> LiteralOperand/8576
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(596, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  595,  true),
					(39,  8576,  false),
					(40,  76,  false),
				});

				// Default XML, i=599, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- AttributeOperand/598
				//	HasDescription/39 -> AttributeOperand/8579
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(599, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  598,  true),
					(39,  8579,  false),
					(40,  76,  false),
				});

				// Default XML, i=602, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SimpleAttributeOperand/601
				//	HasDescription/39 -> SimpleAttributeOperand/8582
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(602, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  601,  true),
					(39,  8582,  false),
					(40,  76,  false),
				});

				// Default XML, i=660, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- HistoryEvent/659
				//	HasDescription/39 -> HistoryEvent/8639
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(660, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  659,  true),
					(39,  8639,  false),
					(40,  76,  false),
				});

				// Default XML, i=720, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- MonitoringFilter/719
				//	HasDescription/39 -> MonitoringFilter/8702
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(720, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  719,  true),
					(39,  8702,  false),
					(40,  76,  false),
				});

				// Default XML, i=726, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- EventFilter/725
				//	HasDescription/39 -> EventFilter/8708
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(726, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  725,  true),
					(39,  8708,  false),
					(40,  76,  false),
				});

				// Default XML, i=949, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- AggregateConfiguration/948
				//	HasDescription/39 -> AggregateConfiguration/8711
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(949, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  948,  true),
					(39,  8711,  false),
					(40,  76,  false),
				});

				// Default XML, i=921, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- HistoryEventFieldList/920
				//	HasDescription/39 -> HistoryEventFieldList/8807
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(921, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  920,  true),
					(39,  8807,  false),
					(40,  76,  false),
				});

				// Default XML, i=400, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ScalarTestType/399
				//	HasDescription/39 -> ScalarTestType/8384
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(400, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  399,  true),
					(39,  8384,  false),
					(40,  76,  false),
				});

				// Default XML, i=403, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ArrayTestType/402
				//	HasDescription/39 -> ArrayTestType/8387
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(403, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  402,  true),
					(39,  8387,  false),
					(40,  76,  false),
				});

				// Default XML, i=406, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- CompositeTestType/405
				//	HasDescription/39 -> CompositeTestType/8390
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(406, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  405,  true),
					(39,  8390,  false),
					(40,  76,  false),
				});

				// Default XML, i=339, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- BuildInfo/338
				//	HasDescription/39 -> BuildInfo/8327
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(339, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  338,  true),
					(39,  8327,  false),
					(40,  76,  false),
				});

				// Default XML, i=854, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- RedundantServerDataType/853
				//	HasDescription/39 -> RedundantServerDataType/8843
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(854, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  853,  true),
					(39,  8843,  false),
					(40,  76,  false),
				});

				// Default XML, i=11949, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- EndpointUrlListDataType/11943
				//	HasDescription/39 -> EndpointUrlListDataType/11951
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(11949, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  11943,  true),
					(39,  11951,  false),
					(40,  76,  false),
				});

				// Default XML, i=11950, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- NetworkGroupDataType/11944
				//	HasDescription/39 -> NetworkGroupDataType/11954
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(11950, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  11944,  true),
					(39,  11954,  false),
					(40,  76,  false),
				});

				// Default XML, i=857, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SamplingIntervalDiagnosticsDataType/856
				//	HasDescription/39 -> SamplingIntervalDiagnosticsDataType/8846
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(857, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  856,  true),
					(39,  8846,  false),
					(40,  76,  false),
				});

				// Default XML, i=860, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ServerDiagnosticsSummaryDataType/859
				//	HasDescription/39 -> ServerDiagnosticsSummaryDataType/8849
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(860, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  859,  true),
					(39,  8849,  false),
					(40,  76,  false),
				});

				// Default XML, i=863, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ServerStatusDataType/862
				//	HasDescription/39 -> ServerStatusDataType/8852
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(863, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  862,  true),
					(39,  8852,  false),
					(40,  76,  false),
				});

				// Default XML, i=866, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SessionDiagnosticsDataType/865
				//	HasDescription/39 -> SessionDiagnosticsDataType/8855
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(866, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  865,  true),
					(39,  8855,  false),
					(40,  76,  false),
				});

				// Default XML, i=869, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SessionSecurityDiagnosticsDataType/868
				//	HasDescription/39 -> SessionSecurityDiagnosticsDataType/8858
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(869, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  868,  true),
					(39,  8858,  false),
					(40,  76,  false),
				});

				// Default XML, i=872, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ServiceCounterDataType/871
				//	HasDescription/39 -> ServiceCounterDataType/8861
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(872, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  871,  true),
					(39,  8861,  false),
					(40,  76,  false),
				});

				// Default XML, i=300, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- StatusResult/299
				//	HasDescription/39 -> StatusResult/8294
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(300, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  299,  true),
					(39,  8294,  false),
					(40,  76,  false),
				});

				// Default XML, i=875, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SubscriptionDiagnosticsDataType/874
				//	HasDescription/39 -> SubscriptionDiagnosticsDataType/8864
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(875, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  874,  true),
					(39,  8864,  false),
					(40,  76,  false),
				});

				// Default XML, i=878, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ModelChangeStructureDataType/877
				//	HasDescription/39 -> ModelChangeStructureDataType/8867
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(878, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  877,  true),
					(39,  8867,  false),
					(40,  76,  false),
				});

				// Default XML, i=898, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SemanticChangeStructureDataType/897
				//	HasDescription/39 -> SemanticChangeStructureDataType/8870
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(898, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  897,  true),
					(39,  8870,  false),
					(40,  76,  false),
				});

				// Default XML, i=885, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- Range/884
				//	HasDescription/39 -> Range/8873
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(885, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  884,  true),
					(39,  8873,  false),
					(40,  76,  false),
				});

				// Default XML, i=888, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- EUInformation/887
				//	HasDescription/39 -> EUInformation/8876
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(888, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  887,  true),
					(39,  8876,  false),
					(40,  76,  false),
				});

				// Default XML, i=12173, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ComplexNumberType/12171
				//	HasDescription/39 -> ComplexNumberType/12175
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(12173, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  12171,  true),
					(39,  12175,  false),
					(40,  76,  false),
				});

				// Default XML, i=12174, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- DoubleComplexNumberType/12172
				//	HasDescription/39 -> DoubleComplexNumberType/12178
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(12174, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  12172,  true),
					(39,  12178,  false),
					(40,  76,  false),
				});

				// Default XML, i=12081, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- AxisInformation/12079
				//	HasDescription/39 -> AxisInformation/12083
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(12081, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  12079,  true),
					(39,  12083,  false),
					(40,  76,  false),
				});

				// Default XML, i=12082, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- XVType/12080
				//	HasDescription/39 -> XVType/12086
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(12082, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  12080,  true),
					(39,  12086,  false),
					(40,  76,  false),
				});

				// Default XML, i=895, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ProgramDiagnosticDataType/894
				//	HasDescription/39 -> ProgramDiagnosticDataType/8882
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(895, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  894,  true),
					(39,  8882,  false),
					(40,  76,  false),
				});

				// Default XML, i=892, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- Annotation/891
				//	HasDescription/39 -> Annotation/8879
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(892, "Default XML", "Default XML", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  891,  true),
					(39,  8879,  false),
					(40,  76,  false),
				});

				// Default Binary, i=298, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- Argument/296
				//	HasDescription/39 -> Argument/7650
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(298, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  296,  true),
					(39,  7650,  false),
					(40,  76,  false),
				});

				// Default Binary, i=8251, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- EnumValueType/7594
				//	HasDescription/39 -> EnumValueType/7656
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(8251, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  7594,  true),
					(39,  7656,  false),
					(40,  76,  false),
				});

				// Default Binary, i=8917, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- TimeZoneDataType/8912
				//	HasDescription/39 -> TimeZoneDataType/8914
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(8917, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  8912,  true),
					(39,  8914,  false),
					(40,  76,  false),
				});

				// Default Binary, i=310, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ApplicationDescription/308
				//	HasDescription/39 -> ApplicationDescription/7665
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(310, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  308,  true),
					(39,  7665,  false),
					(40,  76,  false),
				});

				// Default Binary, i=306, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- UserTokenPolicy/304
				//	HasDescription/39 -> UserTokenPolicy/7662
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(306, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  304,  true),
					(39,  7662,  false),
					(40,  76,  false),
				});
			}
			private void Part6()
			{
				// Default Binary, i=314, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- EndpointDescription/312
				//	HasDescription/39 -> EndpointDescription/7668
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(314, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  312,  true),
					(39,  7668,  false),
					(40,  76,  false),
				});

				// Default Binary, i=434, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- RegisteredServer/432
				//	HasDescription/39 -> RegisteredServer/7782
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(434, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  432,  true),
					(39,  7782,  false),
					(40,  76,  false),
				});

				// Default Binary, i=346, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SignedSoftwareCertificate/344
				//	HasDescription/39 -> SignedSoftwareCertificate/7698
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(346, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  344,  true),
					(39,  7698,  false),
					(40,  76,  false),
				});

				// Default Binary, i=318, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- UserIdentityToken/316
				//	HasDescription/39 -> UserIdentityToken/7671
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(318, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  316,  true),
					(39,  7671,  false),
					(40,  76,  false),
				});

				// Default Binary, i=321, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- AnonymousIdentityToken/319
				//	HasDescription/39 -> AnonymousIdentityToken/7674
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(321, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  319,  true),
					(39,  7674,  false),
					(40,  76,  false),
				});

				// Default Binary, i=324, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- UserNameIdentityToken/322
				//	HasDescription/39 -> UserNameIdentityToken/7677
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(324, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  322,  true),
					(39,  7677,  false),
					(40,  76,  false),
				});

				// Default Binary, i=327, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- X509IdentityToken/325
				//	HasDescription/39 -> X509IdentityToken/7680
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(327, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  325,  true),
					(39,  7680,  false),
					(40,  76,  false),
				});

				// Default Binary, i=940, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- IssuedIdentityToken/938
				//	HasDescription/39 -> IssuedIdentityToken/7683
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(940, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  938,  true),
					(39,  7683,  false),
					(40,  76,  false),
				});

				// Default Binary, i=378, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- AddNodesItem/376
				//	HasDescription/39 -> AddNodesItem/7728
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(378, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  376,  true),
					(39,  7728,  false),
					(40,  76,  false),
				});

				// Default Binary, i=381, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- AddReferencesItem/379
				//	HasDescription/39 -> AddReferencesItem/7731
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(381, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  379,  true),
					(39,  7731,  false),
					(40,  76,  false),
				});

				// Default Binary, i=384, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- DeleteNodesItem/382
				//	HasDescription/39 -> DeleteNodesItem/7734
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(384, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  382,  true),
					(39,  7734,  false),
					(40,  76,  false),
				});

				// Default Binary, i=387, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- DeleteReferencesItem/385
				//	HasDescription/39 -> DeleteReferencesItem/7737
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(387, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  385,  true),
					(39,  7737,  false),
					(40,  76,  false),
				});

				// Default Binary, i=333, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- EndpointConfiguration/331
				//	HasDescription/39 -> EndpointConfiguration/7686
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(333, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  331,  true),
					(39,  7686,  false),
					(40,  76,  false),
				});

				// Default Binary, i=337, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SupportedProfile/335
				//	HasDescription/39 -> SupportedProfile/7689
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(337, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  335,  true),
					(39,  7689,  false),
					(40,  76,  false),
				});

				// Default Binary, i=343, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SoftwareCertificate/341
				//	HasDescription/39 -> SoftwareCertificate/7695
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(343, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  341,  true),
					(39,  7695,  false),
					(40,  76,  false),
				});

				// Default Binary, i=585, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ContentFilterElement/583
				//	HasDescription/39 -> ContentFilterElement/7929
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(585, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  583,  true),
					(39,  7929,  false),
					(40,  76,  false),
				});

				// Default Binary, i=588, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ContentFilter/586
				//	HasDescription/39 -> ContentFilter/7932
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(588, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  586,  true),
					(39,  7932,  false),
					(40,  76,  false),
				});

				// Default Binary, i=591, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- FilterOperand/589
				//	HasDescription/39 -> FilterOperand/7935
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(591, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  589,  true),
					(39,  7935,  false),
					(40,  76,  false),
				});

				// Default Binary, i=594, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ElementOperand/592
				//	HasDescription/39 -> ElementOperand/7938
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(594, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  592,  true),
					(39,  7938,  false),
					(40,  76,  false),
				});

				// Default Binary, i=597, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- LiteralOperand/595
				//	HasDescription/39 -> LiteralOperand/7941
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(597, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  595,  true),
					(39,  7941,  false),
					(40,  76,  false),
				});

				// Default Binary, i=600, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- AttributeOperand/598
				//	HasDescription/39 -> AttributeOperand/7944
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(600, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  598,  true),
					(39,  7944,  false),
					(40,  76,  false),
				});

				// Default Binary, i=603, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SimpleAttributeOperand/601
				//	HasDescription/39 -> SimpleAttributeOperand/7947
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(603, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  601,  true),
					(39,  7947,  false),
					(40,  76,  false),
				});

				// Default Binary, i=661, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- HistoryEvent/659
				//	HasDescription/39 -> HistoryEvent/8004
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(661, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  659,  true),
					(39,  8004,  false),
					(40,  76,  false),
				});

				// Default Binary, i=721, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- MonitoringFilter/719
				//	HasDescription/39 -> MonitoringFilter/8067
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(721, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  719,  true),
					(39,  8067,  false),
					(40,  76,  false),
				});

				// Default Binary, i=727, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- EventFilter/725
				//	HasDescription/39 -> EventFilter/8073
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(727, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  725,  true),
					(39,  8073,  false),
					(40,  76,  false),
				});

				// Default Binary, i=950, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- AggregateConfiguration/948
				//	HasDescription/39 -> AggregateConfiguration/8076
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(950, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  948,  true),
					(39,  8076,  false),
					(40,  76,  false),
				});

				// Default Binary, i=922, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- HistoryEventFieldList/920
				//	HasDescription/39 -> HistoryEventFieldList/8172
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(922, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  920,  true),
					(39,  8172,  false),
					(40,  76,  false),
				});

				// Default Binary, i=401, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ScalarTestType/399
				//	HasDescription/39 -> ScalarTestType/7749
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(401, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  399,  true),
					(39,  7749,  false),
					(40,  76,  false),
				});

				// Default Binary, i=404, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ArrayTestType/402
				//	HasDescription/39 -> ArrayTestType/7752
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(404, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  402,  true),
					(39,  7752,  false),
					(40,  76,  false),
				});

				// Default Binary, i=407, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- CompositeTestType/405
				//	HasDescription/39 -> CompositeTestType/7755
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(407, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  405,  true),
					(39,  7755,  false),
					(40,  76,  false),
				});

				// Default Binary, i=340, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- BuildInfo/338
				//	HasDescription/39 -> BuildInfo/7692
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(340, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  338,  true),
					(39,  7692,  false),
					(40,  76,  false),
				});

				// Default Binary, i=855, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- RedundantServerDataType/853
				//	HasDescription/39 -> RedundantServerDataType/8208
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(855, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  853,  true),
					(39,  8208,  false),
					(40,  76,  false),
				});

				// Default Binary, i=11957, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- EndpointUrlListDataType/11943
				//	HasDescription/39 -> EndpointUrlListDataType/11959
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(11957, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  11943,  true),
					(39,  11959,  false),
					(40,  76,  false),
				});

				// Default Binary, i=11958, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- NetworkGroupDataType/11944
				//	HasDescription/39 -> NetworkGroupDataType/11962
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(11958, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  11944,  true),
					(39,  11962,  false),
					(40,  76,  false),
				});

				// Default Binary, i=858, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SamplingIntervalDiagnosticsDataType/856
				//	HasDescription/39 -> SamplingIntervalDiagnosticsDataType/8211
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(858, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  856,  true),
					(39,  8211,  false),
					(40,  76,  false),
				});

				// Default Binary, i=861, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ServerDiagnosticsSummaryDataType/859
				//	HasDescription/39 -> ServerDiagnosticsSummaryDataType/8214
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(861, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  859,  true),
					(39,  8214,  false),
					(40,  76,  false),
				});

				// Default Binary, i=864, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ServerStatusDataType/862
				//	HasDescription/39 -> ServerStatusDataType/8217
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(864, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  862,  true),
					(39,  8217,  false),
					(40,  76,  false),
				});

				// Default Binary, i=867, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SessionDiagnosticsDataType/865
				//	HasDescription/39 -> SessionDiagnosticsDataType/8220
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(867, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  865,  true),
					(39,  8220,  false),
					(40,  76,  false),
				});

				// Default Binary, i=870, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SessionSecurityDiagnosticsDataType/868
				//	HasDescription/39 -> SessionSecurityDiagnosticsDataType/8223
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(870, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  868,  true),
					(39,  8223,  false),
					(40,  76,  false),
				});

				// Default Binary, i=873, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ServiceCounterDataType/871
				//	HasDescription/39 -> ServiceCounterDataType/8226
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(873, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  871,  true),
					(39,  8226,  false),
					(40,  76,  false),
				});

				// Default Binary, i=301, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- StatusResult/299
				//	HasDescription/39 -> StatusResult/7659
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(301, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  299,  true),
					(39,  7659,  false),
					(40,  76,  false),
				});

				// Default Binary, i=876, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SubscriptionDiagnosticsDataType/874
				//	HasDescription/39 -> SubscriptionDiagnosticsDataType/8229
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(876, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  874,  true),
					(39,  8229,  false),
					(40,  76,  false),
				});

				// Default Binary, i=879, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ModelChangeStructureDataType/877
				//	HasDescription/39 -> ModelChangeStructureDataType/8232
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(879, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  877,  true),
					(39,  8232,  false),
					(40,  76,  false),
				});

				// Default Binary, i=899, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- SemanticChangeStructureDataType/897
				//	HasDescription/39 -> SemanticChangeStructureDataType/8235
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(899, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  897,  true),
					(39,  8235,  false),
					(40,  76,  false),
				});

				// Default Binary, i=886, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- Range/884
				//	HasDescription/39 -> Range/8238
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(886, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  884,  true),
					(39,  8238,  false),
					(40,  76,  false),
				});

				// Default Binary, i=889, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- EUInformation/887
				//	HasDescription/39 -> EUInformation/8241
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(889, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  887,  true),
					(39,  8241,  false),
					(40,  76,  false),
				});

				// Default Binary, i=12181, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ComplexNumberType/12171
				//	HasDescription/39 -> ComplexNumberType/12183
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(12181, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  12171,  true),
					(39,  12183,  false),
					(40,  76,  false),
				});

				// Default Binary, i=12182, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- DoubleComplexNumberType/12172
				//	HasDescription/39 -> DoubleComplexNumberType/12186
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(12182, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  12172,  true),
					(39,  12186,  false),
					(40,  76,  false),
				});

				// Default Binary, i=12089, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- AxisInformation/12079
				//	HasDescription/39 -> AxisInformation/12091
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(12089, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  12079,  true),
					(39,  12091,  false),
					(40,  76,  false),
				});

				// Default Binary, i=12090, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- XVType/12080
				//	HasDescription/39 -> XVType/12094
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(12090, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  12080,  true),
					(39,  12094,  false),
					(40,  76,  false),
				});

				// Default Binary, i=896, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- ProgramDiagnosticDataType/894
				//	HasDescription/39 -> ProgramDiagnosticDataType/8247
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(896, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  894,  true),
					(39,  8247,  false),
					(40,  76,  false),
				});

				// Default Binary, i=893, TypeGenerator.AddressSpaceGenerator+NodeObject
				//	HasEncoding/38 <- Annotation/891
				//	HasDescription/39 -> Annotation/8244
				//	HasTypeDefinition/40 -> DataTypeEncodingType/76
				AddDefaultAddressSpaceNodeObject(893, "Default Binary", "Default Binary", "", 0, 0, 0, new (uint referenceType, uint target, bool isInverse)[] {
					(38,  891,  true),
					(39,  8244,  false),
					(40,  76,  false),
				});

				// DataTypeVersion, i=104, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- DataTypeDescriptionType/69
				AddDefaultAddressSpaceNodeVariable(104, "DataTypeVersion", "DataTypeVersion", "The version number for the data type description.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  69,  true),
				});

				// DictionaryFragment, i=105, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- DataTypeDescriptionType/69
				AddDefaultAddressSpaceNodeVariable(105, "DictionaryFragment", "DictionaryFragment", "A fragment of a data type dictionary that defines the data type.", 0, 0, 0, 0, 0, false, 15, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  69,  true),
				});

				// DataTypeVersion, i=106, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- DataTypeDictionaryType/72
				AddDefaultAddressSpaceNodeVariable(106, "DataTypeVersion", "DataTypeVersion", "The version number for the data type dictionary.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  72,  true),
				});

				// NamespaceUri, i=107, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- DataTypeDictionaryType/72
				AddDefaultAddressSpaceNodeVariable(107, "NamespaceUri", "NamespaceUri", "A URI that uniquely identifies the dictionary.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  72,  true),
				});

				// EnumValues, i=12169, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NamingRuleType/120
				AddDefaultAddressSpaceNodeVariable(12169, "EnumValues", "EnumValues", "The BrowseName must appear in all instances of the type.", 0, 0, 0, 0, 0, false, 7594, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  120,  true),
				});

				// NamingRule, i=111, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ModellingRuleType/77
				AddDefaultAddressSpaceNodeVariable(111, "NamingRule", "NamingRule", "Specified the significances of the BrowseName when a type is instantiated.", 0, 0, 0, 0, 0, false, 120, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  77,  true),
				});

				// NamingRule, i=112, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- Mandatory/78
				AddDefaultAddressSpaceNodeVariable(112, "NamingRule", "NamingRule", "Specified the significances of the BrowseName when a type is instantiated.", 0, 0, 0, 0, 0, false, 120, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  78,  true),
				});

				// NamingRule, i=113, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- Optional/80
				AddDefaultAddressSpaceNodeVariable(113, "NamingRule", "NamingRule", "Specified the significances of the BrowseName when a type is instantiated.", 0, 0, 0, 0, 0, false, 120, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  80,  true),
				});

				// NamingRule, i=114, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ExposesItsArray/83
				AddDefaultAddressSpaceNodeVariable(114, "NamingRule", "NamingRule", "Specified the significances of the BrowseName when a type is instantiated.", 0, 0, 0, 0, 0, false, 120, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  83,  true),
				});

				// NamingRule, i=116, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- MandatoryShared/79
				AddDefaultAddressSpaceNodeVariable(116, "NamingRule", "NamingRule", "Specified the significances of the BrowseName when a type is instantiated.", 0, 0, 0, 0, 0, false, 120, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  79,  true),
				});

				// NamingRule, i=11509, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- OptionalPlaceholder/11508
				AddDefaultAddressSpaceNodeVariable(11509, "NamingRule", "NamingRule", "Specified the significances of the BrowseName when a type is instantiated.", 0, 0, 0, 0, 0, false, 120, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11508,  true),
				});

				// NamingRule, i=11511, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- MandatoryPlaceholder/11510
				AddDefaultAddressSpaceNodeVariable(11511, "NamingRule", "NamingRule", "Specified the significances of the BrowseName when a type is instantiated.", 0, 0, 0, 0, 0, false, 120, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11510,  true),
				});

				// NodeVersion, i=3068, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(3068, "NodeVersion", "NodeVersion", "The version number of the node (used to indicate changes to references of the owning node).", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// ViewVersion, i=12170, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(12170, "ViewVersion", "ViewVersion", "The version number of the view.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// Icon, i=3067, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(3067, "Icon", "Icon", "A small image representing the object.", 0, 0, 0, 0, 0, false, 30, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// LocalTime, i=3069, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(3069, "LocalTime", "LocalTime", "The local time where the owning variable value was collected.", 0, 0, 0, 0, 0, false, 8912, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// AllowNulls, i=3070, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(3070, "AllowNulls", "AllowNulls", "Whether the value of the owning variable is allowed to be null.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// ValueAsText, i=11433, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(11433, "ValueAsText", "ValueAsText", "The string representation of the current value for a variable with an enumerated data type.", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// MaxStringLength, i=11498, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(11498, "MaxStringLength", "MaxStringLength", "The maximum length for a string that can be stored in the owning variable.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// MaxArrayLength, i=11512, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(11512, "MaxArrayLength", "MaxArrayLength", "The maximum length for an array that can be stored in the owning variable.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// EngineeringUnits, i=11513, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(11513, "EngineeringUnits", "EngineeringUnits", "The engineering units for the value of the owning variable.", 0, 0, 0, 0, 0, false, 887, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// EnumStrings, i=11432, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(11432, "EnumStrings", "EnumStrings", "The human readable strings associated with the values of an enumerated value (when values are sequential).", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// EnumValues, i=3071, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(3071, "EnumValues", "EnumValues", "The human readable strings associated with the values of an enumerated value (when values have no sequence).", 0, 0, 0, 0, 0, false, 7594, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// InputArguments, i=3072, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(3072, "InputArguments", "InputArguments", "The input arguments for a method.", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// OutputArguments, i=3073, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(3073, "OutputArguments", "OutputArguments", "The output arguments for a method.", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// ServerArray, i=2005, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerType/2004
				AddDefaultAddressSpaceNodeVariable(2005, "ServerArray", "ServerArray", "The list of server URIs used by the server.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2004,  true),
				});

				// NamespaceArray, i=2006, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerType/2004
				AddDefaultAddressSpaceNodeVariable(2006, "NamespaceArray", "NamespaceArray", "The list of namespace URIs used by the server.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2004,  true),
				});

				// ServerStatus, i=2007, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasComponent/47 -> StartTime/3074
				//	HasComponent/47 -> CurrentTime/3075
				//	HasComponent/47 -> State/3076
				//	HasComponent/47 -> BuildInfo/3077
				//	HasComponent/47 -> SecondsTillShutdown/3084
				//	HasComponent/47 -> ShutdownReason/3085
				//	HasTypeDefinition/40 -> ServerStatusType/2138
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerType/2004
				AddDefaultAddressSpaceNodeVariable(2007, "ServerStatus", "ServerStatus", "The current status of the server.", 0, 0, 0, 0, 0, false, 862, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3074,  false),
					(47,  3075,  false),
					(47,  3076,  false),
					(47,  3077,  false),
					(47,  3084,  false),
					(47,  3085,  false),
					(40,  2138,  false),
					(37,  78,  false),
					(47,  2004,  true),
				});

				// StartTime, i=3074, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerStatus/2007
				AddDefaultAddressSpaceNodeVariable(3074, "StartTime", "StartTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2007,  true),
				});

				// CurrentTime, i=3075, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerStatus/2007
				AddDefaultAddressSpaceNodeVariable(3075, "CurrentTime", "CurrentTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2007,  true),
				});

				// State, i=3076, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerStatus/2007
				AddDefaultAddressSpaceNodeVariable(3076, "State", "State", "", 0, 0, 0, 0, 0, false, 852, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2007,  true),
				});

				// BuildInfo, i=3077, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasComponent/47 -> ProductUri/3078
				//	HasComponent/47 -> ManufacturerName/3079
				//	HasComponent/47 -> ProductName/3080
				//	HasComponent/47 -> SoftwareVersion/3081
				//	HasComponent/47 -> BuildNumber/3082
				//	HasComponent/47 -> BuildDate/3083
				//	HasTypeDefinition/40 -> BuildInfoType/3051
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerStatus/2007
				AddDefaultAddressSpaceNodeVariable(3077, "BuildInfo", "BuildInfo", "", 0, 0, 0, 0, 0, false, 338, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3078,  false),
					(47,  3079,  false),
					(47,  3080,  false),
					(47,  3081,  false),
					(47,  3082,  false),
					(47,  3083,  false),
					(40,  3051,  false),
					(37,  78,  false),
					(47,  2007,  true),
				});

				// ProductUri, i=3078, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfo/3077
				AddDefaultAddressSpaceNodeVariable(3078, "ProductUri", "ProductUri", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3077,  true),
				});

				// ManufacturerName, i=3079, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfo/3077
				AddDefaultAddressSpaceNodeVariable(3079, "ManufacturerName", "ManufacturerName", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3077,  true),
				});

				// ProductName, i=3080, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfo/3077
				AddDefaultAddressSpaceNodeVariable(3080, "ProductName", "ProductName", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3077,  true),
				});

				// SoftwareVersion, i=3081, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfo/3077
				AddDefaultAddressSpaceNodeVariable(3081, "SoftwareVersion", "SoftwareVersion", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3077,  true),
				});

				// BuildNumber, i=3082, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfo/3077
				AddDefaultAddressSpaceNodeVariable(3082, "BuildNumber", "BuildNumber", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3077,  true),
				});

				// BuildDate, i=3083, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfo/3077
				AddDefaultAddressSpaceNodeVariable(3083, "BuildDate", "BuildDate", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3077,  true),
				});

				// SecondsTillShutdown, i=3084, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerStatus/2007
				AddDefaultAddressSpaceNodeVariable(3084, "SecondsTillShutdown", "SecondsTillShutdown", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2007,  true),
				});

				// ShutdownReason, i=3085, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerStatus/2007
				AddDefaultAddressSpaceNodeVariable(3085, "ShutdownReason", "ShutdownReason", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2007,  true),
				});

				// ServiceLevel, i=2008, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerType/2004
				AddDefaultAddressSpaceNodeVariable(2008, "ServiceLevel", "ServiceLevel", "A value indicating the level of service the server can provide. 255 indicates the best.", 0, 0, 0, 0, 0, false, 3, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2004,  true),
				});

				// Auditing, i=2742, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerType/2004
				AddDefaultAddressSpaceNodeVariable(2742, "Auditing", "Auditing", "A flag indicating whether the server is currently generating audit events.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2004,  true),
				});

				// ServerProfileArray, i=3086, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerCapabilities/2009
				AddDefaultAddressSpaceNodeVariable(3086, "ServerProfileArray", "ServerProfileArray", "A list of profiles supported by the server.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2009,  true),
				});

				// LocaleIdArray, i=3087, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerCapabilities/2009
				AddDefaultAddressSpaceNodeVariable(3087, "LocaleIdArray", "LocaleIdArray", "A list of locales supported by the server.", 0, 0, 0, 0, 0, false, 295, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2009,  true),
				});

				// MinSupportedSampleRate, i=3088, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerCapabilities/2009
				AddDefaultAddressSpaceNodeVariable(3088, "MinSupportedSampleRate", "MinSupportedSampleRate", "The minimum sampling interval supported by the server.", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2009,  true),
				});

				// MaxBrowseContinuationPoints, i=3089, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerCapabilities/2009
				AddDefaultAddressSpaceNodeVariable(3089, "MaxBrowseContinuationPoints", "MaxBrowseContinuationPoints", "The maximum number of continuation points for Browse operations per session.", 0, 0, 0, 0, 0, false, 5, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2009,  true),
				});

				// MaxQueryContinuationPoints, i=3090, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerCapabilities/2009
				AddDefaultAddressSpaceNodeVariable(3090, "MaxQueryContinuationPoints", "MaxQueryContinuationPoints", "The maximum number of continuation points for Query operations per session.", 0, 0, 0, 0, 0, false, 5, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2009,  true),
				});

				// MaxHistoryContinuationPoints, i=3091, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerCapabilities/2009
				AddDefaultAddressSpaceNodeVariable(3091, "MaxHistoryContinuationPoints", "MaxHistoryContinuationPoints", "The maximum number of continuation points for ReadHistory operations per session.", 0, 0, 0, 0, 0, false, 5, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2009,  true),
				});

				// SoftwareCertificates, i=3092, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerCapabilities/2009
				AddDefaultAddressSpaceNodeVariable(3092, "SoftwareCertificates", "SoftwareCertificates", "The software certificates owned by the server.", 0, 0, 0, 0, 0, false, 344, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2009,  true),
				});

				// ServerDiagnosticsSummary, i=3095, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasComponent/47 -> ServerViewCount/3096
				//	HasComponent/47 -> CurrentSessionCount/3097
				//	HasComponent/47 -> CumulatedSessionCount/3098
				//	HasComponent/47 -> SecurityRejectedSessionCount/3099
				//	HasComponent/47 -> RejectedSessionCount/3100
				//	HasComponent/47 -> SessionTimeoutCount/3101
				//	HasComponent/47 -> SessionAbortCount/3102
				//	HasComponent/47 -> PublishingIntervalCount/3104
				//	HasComponent/47 -> CurrentSubscriptionCount/3105
				//	HasComponent/47 -> CumulatedSubscriptionCount/3106
				//	HasComponent/47 -> SecurityRejectedRequestsCount/3107
				//	HasComponent/47 -> RejectedRequestsCount/3108
				//	HasTypeDefinition/40 -> ServerDiagnosticsSummaryType/2150
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnostics/2010
				AddDefaultAddressSpaceNodeVariable(3095, "ServerDiagnosticsSummary", "ServerDiagnosticsSummary", "A summary of server level diagnostics.", 0, 0, 0, 0, 0, false, 859, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3096,  false),
					(47,  3097,  false),
					(47,  3098,  false),
					(47,  3099,  false),
					(47,  3100,  false),
					(47,  3101,  false),
					(47,  3102,  false),
					(47,  3104,  false),
					(47,  3105,  false),
					(47,  3106,  false),
					(47,  3107,  false),
					(47,  3108,  false),
					(40,  2150,  false),
					(37,  78,  false),
					(47,  2010,  true),
				});
			}
			private void Part7()
			{
				// ServerViewCount, i=3096, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/3095
				AddDefaultAddressSpaceNodeVariable(3096, "ServerViewCount", "ServerViewCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3095,  true),
				});

				// CurrentSessionCount, i=3097, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/3095
				AddDefaultAddressSpaceNodeVariable(3097, "CurrentSessionCount", "CurrentSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3095,  true),
				});

				// CumulatedSessionCount, i=3098, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/3095
				AddDefaultAddressSpaceNodeVariable(3098, "CumulatedSessionCount", "CumulatedSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3095,  true),
				});

				// SecurityRejectedSessionCount, i=3099, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/3095
				AddDefaultAddressSpaceNodeVariable(3099, "SecurityRejectedSessionCount", "SecurityRejectedSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3095,  true),
				});

				// RejectedSessionCount, i=3100, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/3095
				AddDefaultAddressSpaceNodeVariable(3100, "RejectedSessionCount", "RejectedSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3095,  true),
				});

				// SessionTimeoutCount, i=3101, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/3095
				AddDefaultAddressSpaceNodeVariable(3101, "SessionTimeoutCount", "SessionTimeoutCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3095,  true),
				});

				// SessionAbortCount, i=3102, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/3095
				AddDefaultAddressSpaceNodeVariable(3102, "SessionAbortCount", "SessionAbortCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3095,  true),
				});

				// PublishingIntervalCount, i=3104, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/3095
				AddDefaultAddressSpaceNodeVariable(3104, "PublishingIntervalCount", "PublishingIntervalCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3095,  true),
				});

				// CurrentSubscriptionCount, i=3105, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/3095
				AddDefaultAddressSpaceNodeVariable(3105, "CurrentSubscriptionCount", "CurrentSubscriptionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3095,  true),
				});

				// CumulatedSubscriptionCount, i=3106, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/3095
				AddDefaultAddressSpaceNodeVariable(3106, "CumulatedSubscriptionCount", "CumulatedSubscriptionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3095,  true),
				});

				// SecurityRejectedRequestsCount, i=3107, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/3095
				AddDefaultAddressSpaceNodeVariable(3107, "SecurityRejectedRequestsCount", "SecurityRejectedRequestsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3095,  true),
				});

				// RejectedRequestsCount, i=3108, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/3095
				AddDefaultAddressSpaceNodeVariable(3108, "RejectedRequestsCount", "RejectedRequestsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3095,  true),
				});

				// SubscriptionDiagnosticsArray, i=3110, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SubscriptionDiagnosticsArrayType/2171
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnostics/2010
				AddDefaultAddressSpaceNodeVariable(3110, "SubscriptionDiagnosticsArray", "SubscriptionDiagnosticsArray", "A list of diagnostics for each active subscription.", 0, 0, 0, 0, 0, false, 874, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2171,  false),
					(37,  78,  false),
					(47,  2010,  true),
				});

				// SessionDiagnosticsArray, i=3112, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SessionDiagnosticsArrayType/2196
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionsDiagnosticsSummary/3111
				AddDefaultAddressSpaceNodeVariable(3112, "SessionDiagnosticsArray", "SessionDiagnosticsArray", "A list of diagnostics for each active session.", 0, 0, 0, 0, 0, false, 865, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2196,  false),
					(37,  78,  false),
					(47,  3111,  true),
				});

				// SessionSecurityDiagnosticsArray, i=3113, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SessionSecurityDiagnosticsArrayType/2243
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionsDiagnosticsSummary/3111
				AddDefaultAddressSpaceNodeVariable(3113, "SessionSecurityDiagnosticsArray", "SessionSecurityDiagnosticsArray", "A list of security related diagnostics for each active session.", 0, 0, 0, 0, 0, false, 868, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2243,  false),
					(37,  78,  false),
					(47,  3111,  true),
				});

				// EnabledFlag, i=3114, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerDiagnostics/2010
				AddDefaultAddressSpaceNodeVariable(3114, "EnabledFlag", "EnabledFlag", "If TRUE the diagnostics collection is enabled.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2010,  true),
				});

				// RedundancySupport, i=3115, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerRedundancy/2012
				AddDefaultAddressSpaceNodeVariable(3115, "RedundancySupport", "RedundancySupport", "Indicates what style of redundancy is supported by the server.", 0, 0, 0, 0, 0, false, 851, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2012,  true),
				});

				// InputArguments, i=11490, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- GetMonitoredItems/11489
				AddDefaultAddressSpaceNodeVariable(11490, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11489,  true),
				});

				// OutputArguments, i=11491, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- GetMonitoredItems/11489
				AddDefaultAddressSpaceNodeVariable(11491, "OutputArguments", "OutputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11489,  true),
				});

				// ServerProfileArray, i=2014, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerCapabilitiesType/2013
				AddDefaultAddressSpaceNodeVariable(2014, "ServerProfileArray", "ServerProfileArray", "A list of profiles supported by the server.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2013,  true),
				});

				// LocaleIdArray, i=2016, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerCapabilitiesType/2013
				AddDefaultAddressSpaceNodeVariable(2016, "LocaleIdArray", "LocaleIdArray", "A list of locales supported by the server.", 0, 0, 0, 0, 0, false, 295, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2013,  true),
				});

				// MinSupportedSampleRate, i=2017, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerCapabilitiesType/2013
				AddDefaultAddressSpaceNodeVariable(2017, "MinSupportedSampleRate", "MinSupportedSampleRate", "The minimum sampling interval supported by the server.", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2013,  true),
				});

				// MaxBrowseContinuationPoints, i=2732, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerCapabilitiesType/2013
				AddDefaultAddressSpaceNodeVariable(2732, "MaxBrowseContinuationPoints", "MaxBrowseContinuationPoints", "The maximum number of continuation points for Browse operations per session.", 0, 0, 0, 0, 0, false, 5, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2013,  true),
				});

				// MaxQueryContinuationPoints, i=2733, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerCapabilitiesType/2013
				AddDefaultAddressSpaceNodeVariable(2733, "MaxQueryContinuationPoints", "MaxQueryContinuationPoints", "The maximum number of continuation points for Query operations per session.", 0, 0, 0, 0, 0, false, 5, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2013,  true),
				});

				// MaxHistoryContinuationPoints, i=2734, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerCapabilitiesType/2013
				AddDefaultAddressSpaceNodeVariable(2734, "MaxHistoryContinuationPoints", "MaxHistoryContinuationPoints", "The maximum number of continuation points for ReadHistory operations per session.", 0, 0, 0, 0, 0, false, 5, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2013,  true),
				});

				// SoftwareCertificates, i=3049, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerCapabilitiesType/2013
				AddDefaultAddressSpaceNodeVariable(3049, "SoftwareCertificates", "SoftwareCertificates", "The software certificates owned by the server.", 0, 0, 0, 0, 0, false, 344, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2013,  true),
				});

				// MaxArrayLength, i=11549, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- ServerCapabilitiesType/2013
				AddDefaultAddressSpaceNodeVariable(11549, "MaxArrayLength", "MaxArrayLength", "The maximum length for an array value supported by the server.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2013,  true),
				});

				// MaxStringLength, i=11550, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- ServerCapabilitiesType/2013
				AddDefaultAddressSpaceNodeVariable(11550, "MaxStringLength", "MaxStringLength", "The maximum length for a string value supported by the server.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2013,  true),
				});

				// <VendorCapability>, i=11562, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> ServerVendorCapabilityType/2137
				//	HasModellingRule/37 -> OptionalPlaceholder/11508
				//	HasComponent/47 <- ServerCapabilitiesType/2013
				AddDefaultAddressSpaceNodeVariable(11562, "<VendorCapability>", "<VendorCapability>", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2137,  false),
					(37,  11508,  false),
					(47,  2013,  true),
				});

				// ServerDiagnosticsSummary, i=2021, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasComponent/47 -> ServerViewCount/3116
				//	HasComponent/47 -> CurrentSessionCount/3117
				//	HasComponent/47 -> CumulatedSessionCount/3118
				//	HasComponent/47 -> SecurityRejectedSessionCount/3119
				//	HasComponent/47 -> RejectedSessionCount/3120
				//	HasComponent/47 -> SessionTimeoutCount/3121
				//	HasComponent/47 -> SessionAbortCount/3122
				//	HasComponent/47 -> PublishingIntervalCount/3124
				//	HasComponent/47 -> CurrentSubscriptionCount/3125
				//	HasComponent/47 -> CumulatedSubscriptionCount/3126
				//	HasComponent/47 -> SecurityRejectedRequestsCount/3127
				//	HasComponent/47 -> RejectedRequestsCount/3128
				//	HasTypeDefinition/40 -> ServerDiagnosticsSummaryType/2150
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsType/2020
				AddDefaultAddressSpaceNodeVariable(2021, "ServerDiagnosticsSummary", "ServerDiagnosticsSummary", "A summary of server level diagnostics.", 0, 0, 0, 0, 0, false, 859, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3116,  false),
					(47,  3117,  false),
					(47,  3118,  false),
					(47,  3119,  false),
					(47,  3120,  false),
					(47,  3121,  false),
					(47,  3122,  false),
					(47,  3124,  false),
					(47,  3125,  false),
					(47,  3126,  false),
					(47,  3127,  false),
					(47,  3128,  false),
					(40,  2150,  false),
					(37,  78,  false),
					(47,  2020,  true),
				});

				// ServerViewCount, i=3116, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/2021
				AddDefaultAddressSpaceNodeVariable(3116, "ServerViewCount", "ServerViewCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2021,  true),
				});

				// CurrentSessionCount, i=3117, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/2021
				AddDefaultAddressSpaceNodeVariable(3117, "CurrentSessionCount", "CurrentSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2021,  true),
				});

				// CumulatedSessionCount, i=3118, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/2021
				AddDefaultAddressSpaceNodeVariable(3118, "CumulatedSessionCount", "CumulatedSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2021,  true),
				});

				// SecurityRejectedSessionCount, i=3119, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/2021
				AddDefaultAddressSpaceNodeVariable(3119, "SecurityRejectedSessionCount", "SecurityRejectedSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2021,  true),
				});

				// RejectedSessionCount, i=3120, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/2021
				AddDefaultAddressSpaceNodeVariable(3120, "RejectedSessionCount", "RejectedSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2021,  true),
				});

				// SessionTimeoutCount, i=3121, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/2021
				AddDefaultAddressSpaceNodeVariable(3121, "SessionTimeoutCount", "SessionTimeoutCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2021,  true),
				});

				// SessionAbortCount, i=3122, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/2021
				AddDefaultAddressSpaceNodeVariable(3122, "SessionAbortCount", "SessionAbortCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2021,  true),
				});

				// PublishingIntervalCount, i=3124, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/2021
				AddDefaultAddressSpaceNodeVariable(3124, "PublishingIntervalCount", "PublishingIntervalCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2021,  true),
				});

				// CurrentSubscriptionCount, i=3125, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/2021
				AddDefaultAddressSpaceNodeVariable(3125, "CurrentSubscriptionCount", "CurrentSubscriptionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2021,  true),
				});

				// CumulatedSubscriptionCount, i=3126, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/2021
				AddDefaultAddressSpaceNodeVariable(3126, "CumulatedSubscriptionCount", "CumulatedSubscriptionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2021,  true),
				});

				// SecurityRejectedRequestsCount, i=3127, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/2021
				AddDefaultAddressSpaceNodeVariable(3127, "SecurityRejectedRequestsCount", "SecurityRejectedRequestsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2021,  true),
				});

				// RejectedRequestsCount, i=3128, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummary/2021
				AddDefaultAddressSpaceNodeVariable(3128, "RejectedRequestsCount", "RejectedRequestsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2021,  true),
				});

				// SamplingIntervalDiagnosticsArray, i=2022, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SamplingIntervalDiagnosticsArrayType/2164
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- ServerDiagnosticsType/2020
				AddDefaultAddressSpaceNodeVariable(2022, "SamplingIntervalDiagnosticsArray", "SamplingIntervalDiagnosticsArray", "A list of diagnostics for each sampling interval supported by the server.", 0, 0, 0, 0, 0, false, 856, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2164,  false),
					(37,  80,  false),
					(47,  2020,  true),
				});

				// SubscriptionDiagnosticsArray, i=2023, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SubscriptionDiagnosticsArrayType/2171
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsType/2020
				AddDefaultAddressSpaceNodeVariable(2023, "SubscriptionDiagnosticsArray", "SubscriptionDiagnosticsArray", "A list of diagnostics for each active subscription.", 0, 0, 0, 0, 0, false, 874, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2171,  false),
					(37,  78,  false),
					(47,  2020,  true),
				});

				// SessionDiagnosticsArray, i=3129, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SessionDiagnosticsArrayType/2196
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionsDiagnosticsSummary/2744
				AddDefaultAddressSpaceNodeVariable(3129, "SessionDiagnosticsArray", "SessionDiagnosticsArray", "A list of diagnostics for each active session.", 0, 0, 0, 0, 0, false, 865, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2196,  false),
					(37,  78,  false),
					(47,  2744,  true),
				});

				// SessionSecurityDiagnosticsArray, i=3130, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SessionSecurityDiagnosticsArrayType/2243
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionsDiagnosticsSummary/2744
				AddDefaultAddressSpaceNodeVariable(3130, "SessionSecurityDiagnosticsArray", "SessionSecurityDiagnosticsArray", "A list of security related diagnostics for each active session.", 0, 0, 0, 0, 0, false, 868, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2243,  false),
					(37,  78,  false),
					(47,  2744,  true),
				});

				// EnabledFlag, i=2025, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerDiagnosticsType/2020
				AddDefaultAddressSpaceNodeVariable(2025, "EnabledFlag", "EnabledFlag", "If TRUE the diagnostics collection is enabled.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2020,  true),
				});

				// SessionDiagnosticsArray, i=2027, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SessionDiagnosticsArrayType/2196
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionsDiagnosticsSummaryType/2026
				AddDefaultAddressSpaceNodeVariable(2027, "SessionDiagnosticsArray", "SessionDiagnosticsArray", "A list of diagnostics for each active session.", 0, 0, 0, 0, 0, false, 865, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2196,  false),
					(37,  78,  false),
					(47,  2026,  true),
				});

				// SessionSecurityDiagnosticsArray, i=2028, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SessionSecurityDiagnosticsArrayType/2243
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionsDiagnosticsSummaryType/2026
				AddDefaultAddressSpaceNodeVariable(2028, "SessionSecurityDiagnosticsArray", "SessionSecurityDiagnosticsArray", "A list of security related diagnostics for each active session.", 0, 0, 0, 0, 0, false, 868, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2243,  false),
					(37,  78,  false),
					(47,  2026,  true),
				});

				// SessionDiagnostics, i=12098, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasComponent/47 -> SessionId/12099
				//	HasComponent/47 -> SessionName/12100
				//	HasComponent/47 -> ClientDescription/12101
				//	HasComponent/47 -> ServerUri/12102
				//	HasComponent/47 -> EndpointUrl/12103
				//	HasComponent/47 -> LocaleIds/12104
				//	HasComponent/47 -> ActualSessionTimeout/12105
				//	HasComponent/47 -> MaxResponseMessageSize/12106
				//	HasComponent/47 -> ClientConnectionTime/12107
				//	HasComponent/47 -> ClientLastContactTime/12108
				//	HasComponent/47 -> CurrentSubscriptionsCount/12109
				//	HasComponent/47 -> CurrentMonitoredItemsCount/12110
				//	HasComponent/47 -> CurrentPublishRequestsInQueue/12111
				//	HasComponent/47 -> TotalRequestCount/12112
				//	HasComponent/47 -> UnauthorizedRequestCount/12113
				//	HasComponent/47 -> ReadCount/12114
				//	HasComponent/47 -> HistoryReadCount/12115
				//	HasComponent/47 -> WriteCount/12116
				//	HasComponent/47 -> HistoryUpdateCount/12117
				//	HasComponent/47 -> CallCount/12118
				//	HasComponent/47 -> CreateMonitoredItemsCount/12119
				//	HasComponent/47 -> ModifyMonitoredItemsCount/12120
				//	HasComponent/47 -> SetMonitoringModeCount/12121
				//	HasComponent/47 -> SetTriggeringCount/12122
				//	HasComponent/47 -> DeleteMonitoredItemsCount/12123
				//	HasComponent/47 -> CreateSubscriptionCount/12124
				//	HasComponent/47 -> ModifySubscriptionCount/12125
				//	HasComponent/47 -> SetPublishingModeCount/12126
				//	HasComponent/47 -> PublishCount/12127
				//	HasComponent/47 -> RepublishCount/12128
				//	HasComponent/47 -> TransferSubscriptionsCount/12129
				//	HasComponent/47 -> DeleteSubscriptionsCount/12130
				//	HasComponent/47 -> AddNodesCount/12131
				//	HasComponent/47 -> AddReferencesCount/12132
				//	HasComponent/47 -> DeleteNodesCount/12133
				//	HasComponent/47 -> DeleteReferencesCount/12134
				//	HasComponent/47 -> BrowseCount/12135
				//	HasComponent/47 -> BrowseNextCount/12136
				//	HasComponent/47 -> TranslateBrowsePathsToNodeIdsCount/12137
				//	HasComponent/47 -> QueryFirstCount/12138
				//	HasComponent/47 -> QueryNextCount/12139
				//	HasComponent/47 -> RegisterNodesCount/12140
				//	HasComponent/47 -> UnregisterNodesCount/12141
				//	HasTypeDefinition/40 -> SessionDiagnosticsVariableType/2197
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- <SessionPlaceholder>/12097
				AddDefaultAddressSpaceNodeVariable(12098, "SessionDiagnostics", "SessionDiagnostics", "Diagnostics information for an active session.", 0, 0, 0, 0, 0, false, 865, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  12099,  false),
					(47,  12100,  false),
					(47,  12101,  false),
					(47,  12102,  false),
					(47,  12103,  false),
					(47,  12104,  false),
					(47,  12105,  false),
					(47,  12106,  false),
					(47,  12107,  false),
					(47,  12108,  false),
					(47,  12109,  false),
					(47,  12110,  false),
					(47,  12111,  false),
					(47,  12112,  false),
					(47,  12113,  false),
					(47,  12114,  false),
					(47,  12115,  false),
					(47,  12116,  false),
					(47,  12117,  false),
					(47,  12118,  false),
					(47,  12119,  false),
					(47,  12120,  false),
					(47,  12121,  false),
					(47,  12122,  false),
					(47,  12123,  false),
					(47,  12124,  false),
					(47,  12125,  false),
					(47,  12126,  false),
					(47,  12127,  false),
					(47,  12128,  false),
					(47,  12129,  false),
					(47,  12130,  false),
					(47,  12131,  false),
					(47,  12132,  false),
					(47,  12133,  false),
					(47,  12134,  false),
					(47,  12135,  false),
					(47,  12136,  false),
					(47,  12137,  false),
					(47,  12138,  false),
					(47,  12139,  false),
					(47,  12140,  false),
					(47,  12141,  false),
					(40,  2197,  false),
					(37,  78,  false),
					(47,  12097,  true),
				});

				// SessionId, i=12099, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12099, "SessionId", "SessionId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// SessionName, i=12100, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12100, "SessionName", "SessionName", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// ClientDescription, i=12101, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12101, "ClientDescription", "ClientDescription", "", 0, 0, 0, 0, 0, false, 308, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// ServerUri, i=12102, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12102, "ServerUri", "ServerUri", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// EndpointUrl, i=12103, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12103, "EndpointUrl", "EndpointUrl", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// LocaleIds, i=12104, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12104, "LocaleIds", "LocaleIds", "", 0, 0, 0, 0, 0, false, 295, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// ActualSessionTimeout, i=12105, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12105, "ActualSessionTimeout", "ActualSessionTimeout", "", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// MaxResponseMessageSize, i=12106, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12106, "MaxResponseMessageSize", "MaxResponseMessageSize", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// ClientConnectionTime, i=12107, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12107, "ClientConnectionTime", "ClientConnectionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// ClientLastContactTime, i=12108, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12108, "ClientLastContactTime", "ClientLastContactTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// CurrentSubscriptionsCount, i=12109, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12109, "CurrentSubscriptionsCount", "CurrentSubscriptionsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// CurrentMonitoredItemsCount, i=12110, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12110, "CurrentMonitoredItemsCount", "CurrentMonitoredItemsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// CurrentPublishRequestsInQueue, i=12111, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12111, "CurrentPublishRequestsInQueue", "CurrentPublishRequestsInQueue", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// TotalRequestCount, i=12112, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12112, "TotalRequestCount", "TotalRequestCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// UnauthorizedRequestCount, i=12113, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12113, "UnauthorizedRequestCount", "UnauthorizedRequestCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// ReadCount, i=12114, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12114, "ReadCount", "ReadCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// HistoryReadCount, i=12115, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12115, "HistoryReadCount", "HistoryReadCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// WriteCount, i=12116, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12116, "WriteCount", "WriteCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// HistoryUpdateCount, i=12117, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12117, "HistoryUpdateCount", "HistoryUpdateCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// CallCount, i=12118, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12118, "CallCount", "CallCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// CreateMonitoredItemsCount, i=12119, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12119, "CreateMonitoredItemsCount", "CreateMonitoredItemsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// ModifyMonitoredItemsCount, i=12120, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12120, "ModifyMonitoredItemsCount", "ModifyMonitoredItemsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// SetMonitoringModeCount, i=12121, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12121, "SetMonitoringModeCount", "SetMonitoringModeCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// SetTriggeringCount, i=12122, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12122, "SetTriggeringCount", "SetTriggeringCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// DeleteMonitoredItemsCount, i=12123, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12123, "DeleteMonitoredItemsCount", "DeleteMonitoredItemsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// CreateSubscriptionCount, i=12124, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12124, "CreateSubscriptionCount", "CreateSubscriptionCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// ModifySubscriptionCount, i=12125, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12125, "ModifySubscriptionCount", "ModifySubscriptionCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// SetPublishingModeCount, i=12126, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12126, "SetPublishingModeCount", "SetPublishingModeCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// PublishCount, i=12127, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12127, "PublishCount", "PublishCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// RepublishCount, i=12128, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12128, "RepublishCount", "RepublishCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// TransferSubscriptionsCount, i=12129, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12129, "TransferSubscriptionsCount", "TransferSubscriptionsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// DeleteSubscriptionsCount, i=12130, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12130, "DeleteSubscriptionsCount", "DeleteSubscriptionsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// AddNodesCount, i=12131, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12131, "AddNodesCount", "AddNodesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// AddReferencesCount, i=12132, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12132, "AddReferencesCount", "AddReferencesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// DeleteNodesCount, i=12133, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12133, "DeleteNodesCount", "DeleteNodesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// DeleteReferencesCount, i=12134, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12134, "DeleteReferencesCount", "DeleteReferencesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// BrowseCount, i=12135, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12135, "BrowseCount", "BrowseCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// BrowseNextCount, i=12136, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12136, "BrowseNextCount", "BrowseNextCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// TranslateBrowsePathsToNodeIdsCount, i=12137, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12137, "TranslateBrowsePathsToNodeIdsCount", "TranslateBrowsePathsToNodeIdsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// QueryFirstCount, i=12138, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12138, "QueryFirstCount", "QueryFirstCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

			}
			private void Part8()
			{
				// QueryNextCount, i=12139, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12139, "QueryNextCount", "QueryNextCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// RegisterNodesCount, i=12140, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12140, "RegisterNodesCount", "RegisterNodesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// UnregisterNodesCount, i=12141, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/12098
				AddDefaultAddressSpaceNodeVariable(12141, "UnregisterNodesCount", "UnregisterNodesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12098,  true),
				});

				// SessionSecurityDiagnostics, i=12142, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasComponent/47 -> SessionId/12143
				//	HasComponent/47 -> ClientUserIdOfSession/12144
				//	HasComponent/47 -> ClientUserIdHistory/12145
				//	HasComponent/47 -> AuthenticationMechanism/12146
				//	HasComponent/47 -> Encoding/12147
				//	HasComponent/47 -> TransportProtocol/12148
				//	HasComponent/47 -> SecurityMode/12149
				//	HasComponent/47 -> SecurityPolicyUri/12150
				//	HasComponent/47 -> ClientCertificate/12151
				//	HasTypeDefinition/40 -> SessionSecurityDiagnosticsType/2244
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- <SessionPlaceholder>/12097
				AddDefaultAddressSpaceNodeVariable(12142, "SessionSecurityDiagnostics", "SessionSecurityDiagnostics", "Security related diagnostics information for an active session.", 0, 0, 0, 0, 0, false, 868, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  12143,  false),
					(47,  12144,  false),
					(47,  12145,  false),
					(47,  12146,  false),
					(47,  12147,  false),
					(47,  12148,  false),
					(47,  12149,  false),
					(47,  12150,  false),
					(47,  12151,  false),
					(40,  2244,  false),
					(37,  78,  false),
					(47,  12097,  true),
				});

				// SessionId, i=12143, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/12142
				AddDefaultAddressSpaceNodeVariable(12143, "SessionId", "SessionId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12142,  true),
				});

				// ClientUserIdOfSession, i=12144, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/12142
				AddDefaultAddressSpaceNodeVariable(12144, "ClientUserIdOfSession", "ClientUserIdOfSession", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12142,  true),
				});

				// ClientUserIdHistory, i=12145, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/12142
				AddDefaultAddressSpaceNodeVariable(12145, "ClientUserIdHistory", "ClientUserIdHistory", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12142,  true),
				});

				// AuthenticationMechanism, i=12146, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/12142
				AddDefaultAddressSpaceNodeVariable(12146, "AuthenticationMechanism", "AuthenticationMechanism", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12142,  true),
				});

				// Encoding, i=12147, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/12142
				AddDefaultAddressSpaceNodeVariable(12147, "Encoding", "Encoding", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12142,  true),
				});

				// TransportProtocol, i=12148, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/12142
				AddDefaultAddressSpaceNodeVariable(12148, "TransportProtocol", "TransportProtocol", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12142,  true),
				});

				// SecurityMode, i=12149, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/12142
				AddDefaultAddressSpaceNodeVariable(12149, "SecurityMode", "SecurityMode", "", 0, 0, 0, 0, 0, false, 302, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12142,  true),
				});

				// SecurityPolicyUri, i=12150, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/12142
				AddDefaultAddressSpaceNodeVariable(12150, "SecurityPolicyUri", "SecurityPolicyUri", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12142,  true),
				});

				// ClientCertificate, i=12151, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/12142
				AddDefaultAddressSpaceNodeVariable(12151, "ClientCertificate", "ClientCertificate", "", 0, 0, 0, 0, 0, false, 15, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  12142,  true),
				});

				// SubscriptionDiagnosticsArray, i=12152, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SubscriptionDiagnosticsArrayType/2171
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- <SessionPlaceholder>/12097
				AddDefaultAddressSpaceNodeVariable(12152, "SubscriptionDiagnosticsArray", "SubscriptionDiagnosticsArray", "A list of diagnostics for each subscription owned by the session.", 0, 0, 0, 0, 0, false, 874, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2171,  false),
					(37,  78,  false),
					(47,  12097,  true),
				});

				// SessionDiagnostics, i=2030, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasComponent/47 -> SessionId/3131
				//	HasComponent/47 -> SessionName/3132
				//	HasComponent/47 -> ClientDescription/3133
				//	HasComponent/47 -> ServerUri/3134
				//	HasComponent/47 -> EndpointUrl/3135
				//	HasComponent/47 -> LocaleIds/3136
				//	HasComponent/47 -> ActualSessionTimeout/3137
				//	HasComponent/47 -> MaxResponseMessageSize/3138
				//	HasComponent/47 -> ClientConnectionTime/3139
				//	HasComponent/47 -> ClientLastContactTime/3140
				//	HasComponent/47 -> CurrentSubscriptionsCount/3141
				//	HasComponent/47 -> CurrentMonitoredItemsCount/3142
				//	HasComponent/47 -> CurrentPublishRequestsInQueue/3143
				//	HasComponent/47 -> TotalRequestCount/8898
				//	HasComponent/47 -> UnauthorizedRequestCount/11891
				//	HasComponent/47 -> ReadCount/3151
				//	HasComponent/47 -> HistoryReadCount/3152
				//	HasComponent/47 -> WriteCount/3153
				//	HasComponent/47 -> HistoryUpdateCount/3154
				//	HasComponent/47 -> CallCount/3155
				//	HasComponent/47 -> CreateMonitoredItemsCount/3156
				//	HasComponent/47 -> ModifyMonitoredItemsCount/3157
				//	HasComponent/47 -> SetMonitoringModeCount/3158
				//	HasComponent/47 -> SetTriggeringCount/3159
				//	HasComponent/47 -> DeleteMonitoredItemsCount/3160
				//	HasComponent/47 -> CreateSubscriptionCount/3161
				//	HasComponent/47 -> ModifySubscriptionCount/3162
				//	HasComponent/47 -> SetPublishingModeCount/3163
				//	HasComponent/47 -> PublishCount/3164
				//	HasComponent/47 -> RepublishCount/3165
				//	HasComponent/47 -> TransferSubscriptionsCount/3166
				//	HasComponent/47 -> DeleteSubscriptionsCount/3167
				//	HasComponent/47 -> AddNodesCount/3168
				//	HasComponent/47 -> AddReferencesCount/3169
				//	HasComponent/47 -> DeleteNodesCount/3170
				//	HasComponent/47 -> DeleteReferencesCount/3171
				//	HasComponent/47 -> BrowseCount/3172
				//	HasComponent/47 -> BrowseNextCount/3173
				//	HasComponent/47 -> TranslateBrowsePathsToNodeIdsCount/3174
				//	HasComponent/47 -> QueryFirstCount/3175
				//	HasComponent/47 -> QueryNextCount/3176
				//	HasComponent/47 -> RegisterNodesCount/3177
				//	HasComponent/47 -> UnregisterNodesCount/3178
				//	HasTypeDefinition/40 -> SessionDiagnosticsVariableType/2197
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsObjectType/2029
				AddDefaultAddressSpaceNodeVariable(2030, "SessionDiagnostics", "SessionDiagnostics", "Diagnostics information for an active session.", 0, 0, 0, 0, 0, false, 865, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3131,  false),
					(47,  3132,  false),
					(47,  3133,  false),
					(47,  3134,  false),
					(47,  3135,  false),
					(47,  3136,  false),
					(47,  3137,  false),
					(47,  3138,  false),
					(47,  3139,  false),
					(47,  3140,  false),
					(47,  3141,  false),
					(47,  3142,  false),
					(47,  3143,  false),
					(47,  8898,  false),
					(47,  11891,  false),
					(47,  3151,  false),
					(47,  3152,  false),
					(47,  3153,  false),
					(47,  3154,  false),
					(47,  3155,  false),
					(47,  3156,  false),
					(47,  3157,  false),
					(47,  3158,  false),
					(47,  3159,  false),
					(47,  3160,  false),
					(47,  3161,  false),
					(47,  3162,  false),
					(47,  3163,  false),
					(47,  3164,  false),
					(47,  3165,  false),
					(47,  3166,  false),
					(47,  3167,  false),
					(47,  3168,  false),
					(47,  3169,  false),
					(47,  3170,  false),
					(47,  3171,  false),
					(47,  3172,  false),
					(47,  3173,  false),
					(47,  3174,  false),
					(47,  3175,  false),
					(47,  3176,  false),
					(47,  3177,  false),
					(47,  3178,  false),
					(40,  2197,  false),
					(37,  78,  false),
					(47,  2029,  true),
				});

				// SessionId, i=3131, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3131, "SessionId", "SessionId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// SessionName, i=3132, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3132, "SessionName", "SessionName", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// ClientDescription, i=3133, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3133, "ClientDescription", "ClientDescription", "", 0, 0, 0, 0, 0, false, 308, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// ServerUri, i=3134, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3134, "ServerUri", "ServerUri", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// EndpointUrl, i=3135, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3135, "EndpointUrl", "EndpointUrl", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// LocaleIds, i=3136, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3136, "LocaleIds", "LocaleIds", "", 0, 0, 0, 0, 0, false, 295, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// ActualSessionTimeout, i=3137, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3137, "ActualSessionTimeout", "ActualSessionTimeout", "", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// MaxResponseMessageSize, i=3138, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3138, "MaxResponseMessageSize", "MaxResponseMessageSize", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// ClientConnectionTime, i=3139, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3139, "ClientConnectionTime", "ClientConnectionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// ClientLastContactTime, i=3140, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3140, "ClientLastContactTime", "ClientLastContactTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// CurrentSubscriptionsCount, i=3141, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3141, "CurrentSubscriptionsCount", "CurrentSubscriptionsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// CurrentMonitoredItemsCount, i=3142, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3142, "CurrentMonitoredItemsCount", "CurrentMonitoredItemsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// CurrentPublishRequestsInQueue, i=3143, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3143, "CurrentPublishRequestsInQueue", "CurrentPublishRequestsInQueue", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// TotalRequestCount, i=8898, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(8898, "TotalRequestCount", "TotalRequestCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// UnauthorizedRequestCount, i=11891, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(11891, "UnauthorizedRequestCount", "UnauthorizedRequestCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// ReadCount, i=3151, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3151, "ReadCount", "ReadCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// HistoryReadCount, i=3152, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3152, "HistoryReadCount", "HistoryReadCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// WriteCount, i=3153, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3153, "WriteCount", "WriteCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// HistoryUpdateCount, i=3154, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3154, "HistoryUpdateCount", "HistoryUpdateCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// CallCount, i=3155, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3155, "CallCount", "CallCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// CreateMonitoredItemsCount, i=3156, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3156, "CreateMonitoredItemsCount", "CreateMonitoredItemsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// ModifyMonitoredItemsCount, i=3157, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3157, "ModifyMonitoredItemsCount", "ModifyMonitoredItemsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// SetMonitoringModeCount, i=3158, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3158, "SetMonitoringModeCount", "SetMonitoringModeCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// SetTriggeringCount, i=3159, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3159, "SetTriggeringCount", "SetTriggeringCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// DeleteMonitoredItemsCount, i=3160, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3160, "DeleteMonitoredItemsCount", "DeleteMonitoredItemsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// CreateSubscriptionCount, i=3161, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3161, "CreateSubscriptionCount", "CreateSubscriptionCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// ModifySubscriptionCount, i=3162, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3162, "ModifySubscriptionCount", "ModifySubscriptionCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// SetPublishingModeCount, i=3163, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3163, "SetPublishingModeCount", "SetPublishingModeCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// PublishCount, i=3164, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3164, "PublishCount", "PublishCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// RepublishCount, i=3165, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3165, "RepublishCount", "RepublishCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// TransferSubscriptionsCount, i=3166, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3166, "TransferSubscriptionsCount", "TransferSubscriptionsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// DeleteSubscriptionsCount, i=3167, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3167, "DeleteSubscriptionsCount", "DeleteSubscriptionsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// AddNodesCount, i=3168, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3168, "AddNodesCount", "AddNodesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// AddReferencesCount, i=3169, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3169, "AddReferencesCount", "AddReferencesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// DeleteNodesCount, i=3170, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3170, "DeleteNodesCount", "DeleteNodesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// DeleteReferencesCount, i=3171, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3171, "DeleteReferencesCount", "DeleteReferencesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// BrowseCount, i=3172, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3172, "BrowseCount", "BrowseCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// BrowseNextCount, i=3173, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3173, "BrowseNextCount", "BrowseNextCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// TranslateBrowsePathsToNodeIdsCount, i=3174, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3174, "TranslateBrowsePathsToNodeIdsCount", "TranslateBrowsePathsToNodeIdsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// QueryFirstCount, i=3175, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3175, "QueryFirstCount", "QueryFirstCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// QueryNextCount, i=3176, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3176, "QueryNextCount", "QueryNextCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// RegisterNodesCount, i=3177, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3177, "RegisterNodesCount", "RegisterNodesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// UnregisterNodesCount, i=3178, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnostics/2030
				AddDefaultAddressSpaceNodeVariable(3178, "UnregisterNodesCount", "UnregisterNodesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2030,  true),
				});

				// SessionSecurityDiagnostics, i=2031, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasComponent/47 -> SessionId/3179
				//	HasComponent/47 -> ClientUserIdOfSession/3180
				//	HasComponent/47 -> ClientUserIdHistory/3181
				//	HasComponent/47 -> AuthenticationMechanism/3182
				//	HasComponent/47 -> Encoding/3183
				//	HasComponent/47 -> TransportProtocol/3184
				//	HasComponent/47 -> SecurityMode/3185
				//	HasComponent/47 -> SecurityPolicyUri/3186
				//	HasComponent/47 -> ClientCertificate/3187
				//	HasTypeDefinition/40 -> SessionSecurityDiagnosticsType/2244
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsObjectType/2029
				AddDefaultAddressSpaceNodeVariable(2031, "SessionSecurityDiagnostics", "SessionSecurityDiagnostics", "Security related diagnostics information for an active session.", 0, 0, 0, 0, 0, false, 868, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3179,  false),
					(47,  3180,  false),
					(47,  3181,  false),
					(47,  3182,  false),
					(47,  3183,  false),
					(47,  3184,  false),
					(47,  3185,  false),
					(47,  3186,  false),
					(47,  3187,  false),
					(40,  2244,  false),
					(37,  78,  false),
					(47,  2029,  true),
				});

				// SessionId, i=3179, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/2031
				AddDefaultAddressSpaceNodeVariable(3179, "SessionId", "SessionId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2031,  true),
				});

				// ClientUserIdOfSession, i=3180, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/2031
				AddDefaultAddressSpaceNodeVariable(3180, "ClientUserIdOfSession", "ClientUserIdOfSession", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2031,  true),
				});

				// ClientUserIdHistory, i=3181, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/2031
				AddDefaultAddressSpaceNodeVariable(3181, "ClientUserIdHistory", "ClientUserIdHistory", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2031,  true),
				});

				// AuthenticationMechanism, i=3182, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/2031
				AddDefaultAddressSpaceNodeVariable(3182, "AuthenticationMechanism", "AuthenticationMechanism", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2031,  true),
				});

				// Encoding, i=3183, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/2031
				AddDefaultAddressSpaceNodeVariable(3183, "Encoding", "Encoding", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2031,  true),
				});

				// TransportProtocol, i=3184, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/2031
				AddDefaultAddressSpaceNodeVariable(3184, "TransportProtocol", "TransportProtocol", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2031,  true),
				});

				// SecurityMode, i=3185, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/2031
				AddDefaultAddressSpaceNodeVariable(3185, "SecurityMode", "SecurityMode", "", 0, 0, 0, 0, 0, false, 302, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2031,  true),
				});

				// SecurityPolicyUri, i=3186, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/2031
				AddDefaultAddressSpaceNodeVariable(3186, "SecurityPolicyUri", "SecurityPolicyUri", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2031,  true),
				});

				// ClientCertificate, i=3187, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnostics/2031
				AddDefaultAddressSpaceNodeVariable(3187, "ClientCertificate", "ClientCertificate", "", 0, 0, 0, 0, 0, false, 15, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2031,  true),
				});

				// SubscriptionDiagnosticsArray, i=2032, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SubscriptionDiagnosticsArrayType/2171
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsObjectType/2029
				AddDefaultAddressSpaceNodeVariable(2032, "SubscriptionDiagnosticsArray", "SubscriptionDiagnosticsArray", "A list of diagnostics for each subscription owned by the session.", 0, 0, 0, 0, 0, false, 874, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2171,  false),
					(37,  78,  false),
					(47,  2029,  true),
				});

				// RedundancySupport, i=2035, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerRedundancyType/2034
				AddDefaultAddressSpaceNodeVariable(2035, "RedundancySupport", "RedundancySupport", "Indicates what style of redundancy is supported by the server.", 0, 0, 0, 0, 0, false, 851, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2034,  true),
				});

				// CurrentServerId, i=2037, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- TransparentRedundancyType/2036
				AddDefaultAddressSpaceNodeVariable(2037, "CurrentServerId", "CurrentServerId", "The ID of the server that is currently in use.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2036,  true),
				});

				// RedundantServerArray, i=2038, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- TransparentRedundancyType/2036
				AddDefaultAddressSpaceNodeVariable(2038, "RedundantServerArray", "RedundantServerArray", "A list of servers in the same redundant set.", 0, 0, 0, 0, 0, false, 853, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2036,  true),
				});

				// ServerUriArray, i=2040, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NonTransparentRedundancyType/2039
				AddDefaultAddressSpaceNodeVariable(2040, "ServerUriArray", "ServerUriArray", "A list of servers in the same redundant set.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2039,  true),
				});

				// ServerNetworkGroups, i=11948, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NonTransparentNetworkRedundancyType/11945
				AddDefaultAddressSpaceNodeVariable(11948, "ServerNetworkGroups", "ServerNetworkGroups", "", 0, 0, 0, 0, 0, false, 11944, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11945,  true),
				});

				// MaxNodesPerRead, i=11565, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- OperationLimitsType/11564
				AddDefaultAddressSpaceNodeVariable(11565, "MaxNodesPerRead", "MaxNodesPerRead", "The maximum number of operations in a single Read request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  11564,  true),
				});

				// MaxNodesPerHistoryReadData, i=12161, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- OperationLimitsType/11564
				AddDefaultAddressSpaceNodeVariable(12161, "MaxNodesPerHistoryReadData", "MaxNodesPerHistoryReadData", "The maximum number of operations in a single data HistoryRead request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  11564,  true),
				});

				// MaxNodesPerHistoryReadEvents, i=12162, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- OperationLimitsType/11564
				AddDefaultAddressSpaceNodeVariable(12162, "MaxNodesPerHistoryReadEvents", "MaxNodesPerHistoryReadEvents", "The maximum number of operations in a single event HistoryRead request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  11564,  true),
				});

				// MaxNodesPerWrite, i=11567, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- OperationLimitsType/11564
				AddDefaultAddressSpaceNodeVariable(11567, "MaxNodesPerWrite", "MaxNodesPerWrite", "The maximum number of operations in a single Write request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  11564,  true),
				});

				// MaxNodesPerHistoryUpdateData, i=12163, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- OperationLimitsType/11564
				AddDefaultAddressSpaceNodeVariable(12163, "MaxNodesPerHistoryUpdateData", "MaxNodesPerHistoryUpdateData", "The maximum number of operations in a single data HistoryUpdate request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  11564,  true),
				});

				// MaxNodesPerHistoryUpdateEvents, i=12164, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- OperationLimitsType/11564
				AddDefaultAddressSpaceNodeVariable(12164, "MaxNodesPerHistoryUpdateEvents", "MaxNodesPerHistoryUpdateEvents", "The maximum number of operations in a single event HistoryUpdate request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  11564,  true),
				});

				// MaxNodesPerMethodCall, i=11569, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- OperationLimitsType/11564
				AddDefaultAddressSpaceNodeVariable(11569, "MaxNodesPerMethodCall", "MaxNodesPerMethodCall", "The maximum number of operations in a single Call request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  11564,  true),
				});

				// MaxNodesPerBrowse, i=11570, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- OperationLimitsType/11564
				AddDefaultAddressSpaceNodeVariable(11570, "MaxNodesPerBrowse", "MaxNodesPerBrowse", "The maximum number of operations in a single Browse request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  11564,  true),
				});

				// MaxNodesPerRegisterNodes, i=11571, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- OperationLimitsType/11564
				AddDefaultAddressSpaceNodeVariable(11571, "MaxNodesPerRegisterNodes", "MaxNodesPerRegisterNodes", "The maximum number of operations in a single RegisterNodes request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  11564,  true),
				});

				// MaxNodesPerTranslateBrowsePathsToNodeIds, i=11572, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- OperationLimitsType/11564
				AddDefaultAddressSpaceNodeVariable(11572, "MaxNodesPerTranslateBrowsePathsToNodeIds", "MaxNodesPerTranslateBrowsePathsToNodeIds", "The maximum number of operations in a single TranslateBrowsePathsToNodeIds request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  11564,  true),
				});

				// MaxNodesPerNodeManagement, i=11573, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- OperationLimitsType/11564
				AddDefaultAddressSpaceNodeVariable(11573, "MaxNodesPerNodeManagement", "MaxNodesPerNodeManagement", "The maximum number of operations in a single AddNodes, AddReferences, DeleteNodes or DeleteReferences request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  11564,  true),
				});

				// MaxMonitoredItemsPerCall, i=11574, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- OperationLimitsType/11564
				AddDefaultAddressSpaceNodeVariable(11574, "MaxMonitoredItemsPerCall", "MaxMonitoredItemsPerCall", "The maximum number of operations in a single MonitoredItem related request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  11564,  true),
				});

				// Size, i=11576, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- FileType/11575
				AddDefaultAddressSpaceNodeVariable(11576, "Size", "Size", "The size of the file in bytes.", 0, 0, 0, 0, 0, false, 9, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11575,  true),
				});

				// Writeable, i=11577, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- FileType/11575
				AddDefaultAddressSpaceNodeVariable(11577, "Writeable", "Writeable", "Whether the file is writeable.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11575,  true),
				});

			}
			private void Part9()
			{
				// UserWriteable, i=11578, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- FileType/11575
				AddDefaultAddressSpaceNodeVariable(11578, "UserWriteable", "UserWriteable", "Whether the file is writeable by the current user.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11575,  true),
				});

				// OpenCount, i=11579, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- FileType/11575
				AddDefaultAddressSpaceNodeVariable(11579, "OpenCount", "OpenCount", "The current number of open file handles.", 0, 0, 0, 0, 0, false, 5, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11575,  true),
				});

				// InputArguments, i=11581, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Open/11580
				AddDefaultAddressSpaceNodeVariable(11581, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11580,  true),
				});

				// OutputArguments, i=11582, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Open/11580
				AddDefaultAddressSpaceNodeVariable(11582, "OutputArguments", "OutputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11580,  true),
				});

				// InputArguments, i=11584, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Close/11583
				AddDefaultAddressSpaceNodeVariable(11584, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11583,  true),
				});

				// InputArguments, i=11586, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Read/11585
				AddDefaultAddressSpaceNodeVariable(11586, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11585,  true),
				});

				// OutputArguments, i=11587, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Read/11585
				AddDefaultAddressSpaceNodeVariable(11587, "OutputArguments", "OutputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11585,  true),
				});

				// InputArguments, i=11589, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Write/11588
				AddDefaultAddressSpaceNodeVariable(11589, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11588,  true),
				});

				// InputArguments, i=11591, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- GetPosition/11590
				AddDefaultAddressSpaceNodeVariable(11591, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11590,  true),
				});

				// OutputArguments, i=11592, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- GetPosition/11590
				AddDefaultAddressSpaceNodeVariable(11592, "OutputArguments", "OutputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11590,  true),
				});

				// InputArguments, i=11594, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- SetPosition/11593
				AddDefaultAddressSpaceNodeVariable(11594, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11593,  true),
				});

				// NamespaceUri, i=11617, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NamespaceMetadataType/11616
				AddDefaultAddressSpaceNodeVariable(11617, "NamespaceUri", "NamespaceUri", "The URI of the namespace.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11616,  true),
				});

				// NamespaceVersion, i=11618, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NamespaceMetadataType/11616
				AddDefaultAddressSpaceNodeVariable(11618, "NamespaceVersion", "NamespaceVersion", "The human readable string representing version of the namespace.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11616,  true),
				});

				// NamespacePublicationDate, i=11619, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NamespaceMetadataType/11616
				AddDefaultAddressSpaceNodeVariable(11619, "NamespacePublicationDate", "NamespacePublicationDate", "The publication date for the namespace.", 0, 0, 0, 0, 0, false, 13, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11616,  true),
				});

				// IsNamespaceSubset, i=11620, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NamespaceMetadataType/11616
				AddDefaultAddressSpaceNodeVariable(11620, "IsNamespaceSubset", "IsNamespaceSubset", "If TRUE then the server only supports a subset of the namespace.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11616,  true),
				});

				// StaticNodeIdIdentifierTypes, i=11621, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NamespaceMetadataType/11616
				AddDefaultAddressSpaceNodeVariable(11621, "StaticNodeIdIdentifierTypes", "StaticNodeIdIdentifierTypes", "A list of IdTypes for nodes which are the same in every server that exposes them.", 0, 0, 0, 0, 0, false, 256, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11616,  true),
				});

				// StaticNumericNodeIdRange, i=11622, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NamespaceMetadataType/11616
				AddDefaultAddressSpaceNodeVariable(11622, "StaticNumericNodeIdRange", "StaticNumericNodeIdRange", "A list of ranges for numeric node ids which are the same in every server that exposes them.", 0, 0, 0, 0, 0, false, 291, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11616,  true),
				});

				// StaticStringNodeIdPattern, i=11623, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NamespaceMetadataType/11616
				AddDefaultAddressSpaceNodeVariable(11623, "StaticStringNodeIdPattern", "StaticStringNodeIdPattern", "A regular expression which matches string node ids are the same in every server that exposes them.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11616,  true),
				});

				// Size, i=11625, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NamespaceFile/11624
				AddDefaultAddressSpaceNodeVariable(11625, "Size", "Size", "The size of the file in bytes.", 0, 0, 0, 0, 0, false, 9, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11624,  true),
				});

				// Writeable, i=11626, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NamespaceFile/11624
				AddDefaultAddressSpaceNodeVariable(11626, "Writeable", "Writeable", "Whether the file is writeable.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11624,  true),
				});

				// UserWriteable, i=11627, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NamespaceFile/11624
				AddDefaultAddressSpaceNodeVariable(11627, "UserWriteable", "UserWriteable", "Whether the file is writeable by the current user.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11624,  true),
				});

				// OpenCount, i=11628, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NamespaceFile/11624
				AddDefaultAddressSpaceNodeVariable(11628, "OpenCount", "OpenCount", "The current number of open file handles.", 0, 0, 0, 0, 0, false, 5, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11624,  true),
				});

				// InputArguments, i=11630, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Open/11629
				AddDefaultAddressSpaceNodeVariable(11630, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11629,  true),
				});

				// OutputArguments, i=11631, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Open/11629
				AddDefaultAddressSpaceNodeVariable(11631, "OutputArguments", "OutputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11629,  true),
				});

				// InputArguments, i=11633, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Close/11632
				AddDefaultAddressSpaceNodeVariable(11633, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11632,  true),
				});

				// InputArguments, i=11635, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Read/11634
				AddDefaultAddressSpaceNodeVariable(11635, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11634,  true),
				});

				// OutputArguments, i=11636, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Read/11634
				AddDefaultAddressSpaceNodeVariable(11636, "OutputArguments", "OutputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11634,  true),
				});

				// InputArguments, i=11638, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Write/11637
				AddDefaultAddressSpaceNodeVariable(11638, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11637,  true),
				});

				// InputArguments, i=11640, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- GetPosition/11639
				AddDefaultAddressSpaceNodeVariable(11640, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11639,  true),
				});

				// OutputArguments, i=11641, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- GetPosition/11639
				AddDefaultAddressSpaceNodeVariable(11641, "OutputArguments", "OutputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11639,  true),
				});

				// InputArguments, i=11643, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- SetPosition/11642
				AddDefaultAddressSpaceNodeVariable(11643, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11642,  true),
				});

				// NamespaceUri, i=11647, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- <NamespaceIdentifier>/11646
				AddDefaultAddressSpaceNodeVariable(11647, "NamespaceUri", "NamespaceUri", "The URI of the namespace.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11646,  true),
				});

				// NamespaceVersion, i=11648, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- <NamespaceIdentifier>/11646
				AddDefaultAddressSpaceNodeVariable(11648, "NamespaceVersion", "NamespaceVersion", "The human readable string representing version of the namespace.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11646,  true),
				});

				// NamespacePublicationDate, i=11649, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- <NamespaceIdentifier>/11646
				AddDefaultAddressSpaceNodeVariable(11649, "NamespacePublicationDate", "NamespacePublicationDate", "The publication date for the namespace.", 0, 0, 0, 0, 0, false, 13, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11646,  true),
				});

				// IsNamespaceSubset, i=11650, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- <NamespaceIdentifier>/11646
				AddDefaultAddressSpaceNodeVariable(11650, "IsNamespaceSubset", "IsNamespaceSubset", "If TRUE then the server only supports a subset of the namespace.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11646,  true),
				});

				// StaticNodeIdIdentifierTypes, i=11651, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- <NamespaceIdentifier>/11646
				AddDefaultAddressSpaceNodeVariable(11651, "StaticNodeIdIdentifierTypes", "StaticNodeIdIdentifierTypes", "A list of IdTypes for nodes which are the same in every server that exposes them.", 0, 0, 0, 0, 0, false, 256, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11646,  true),
				});

				// StaticNumericNodeIdRange, i=11652, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- <NamespaceIdentifier>/11646
				AddDefaultAddressSpaceNodeVariable(11652, "StaticNumericNodeIdRange", "StaticNumericNodeIdRange", "A list of ranges for numeric node ids which are the same in every server that exposes them.", 0, 0, 0, 0, 0, false, 291, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11646,  true),
				});

				// StaticStringNodeIdPattern, i=11653, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- <NamespaceIdentifier>/11646
				AddDefaultAddressSpaceNodeVariable(11653, "StaticStringNodeIdPattern", "StaticStringNodeIdPattern", "A regular expression which matches string node ids are the same in every server that exposes them.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11646,  true),
				});

				// Size, i=11676, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AddressSpaceFile/11675
				AddDefaultAddressSpaceNodeVariable(11676, "Size", "Size", "The size of the file in bytes.", 0, 0, 0, 0, 0, false, 9, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11675,  true),
				});

				// Writeable, i=11677, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AddressSpaceFile/11675
				AddDefaultAddressSpaceNodeVariable(11677, "Writeable", "Writeable", "Whether the file is writeable.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11675,  true),
				});

				// UserWriteable, i=11678, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AddressSpaceFile/11675
				AddDefaultAddressSpaceNodeVariable(11678, "UserWriteable", "UserWriteable", "Whether the file is writeable by the current user.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11675,  true),
				});

				// OpenCount, i=11679, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AddressSpaceFile/11675
				AddDefaultAddressSpaceNodeVariable(11679, "OpenCount", "OpenCount", "The current number of open file handles.", 0, 0, 0, 0, 0, false, 5, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11675,  true),
				});

				// InputArguments, i=11681, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Open/11680
				AddDefaultAddressSpaceNodeVariable(11681, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11680,  true),
				});

				// OutputArguments, i=11682, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Open/11680
				AddDefaultAddressSpaceNodeVariable(11682, "OutputArguments", "OutputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11680,  true),
				});

				// InputArguments, i=11684, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Close/11683
				AddDefaultAddressSpaceNodeVariable(11684, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11683,  true),
				});

				// InputArguments, i=11686, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Read/11685
				AddDefaultAddressSpaceNodeVariable(11686, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11685,  true),
				});

				// OutputArguments, i=11687, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Read/11685
				AddDefaultAddressSpaceNodeVariable(11687, "OutputArguments", "OutputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11685,  true),
				});

				// InputArguments, i=11689, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Write/11688
				AddDefaultAddressSpaceNodeVariable(11689, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11688,  true),
				});

				// InputArguments, i=11691, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- GetPosition/11690
				AddDefaultAddressSpaceNodeVariable(11691, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11690,  true),
				});

				// OutputArguments, i=11692, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- GetPosition/11690
				AddDefaultAddressSpaceNodeVariable(11692, "OutputArguments", "OutputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11690,  true),
				});

				// InputArguments, i=11694, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- SetPosition/11693
				AddDefaultAddressSpaceNodeVariable(11694, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11693,  true),
				});

				// EventId, i=2042, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- BaseEventType/2041
				AddDefaultAddressSpaceNodeVariable(2042, "EventId", "EventId", "A globally unique identifier for the event.", 0, 0, 0, 0, 0, false, 15, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2041,  true),
				});

				// EventType, i=2043, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- BaseEventType/2041
				AddDefaultAddressSpaceNodeVariable(2043, "EventType", "EventType", "The identifier for the event type.", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2041,  true),
				});

				// SourceNode, i=2044, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- BaseEventType/2041
				AddDefaultAddressSpaceNodeVariable(2044, "SourceNode", "SourceNode", "The source of the event.", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2041,  true),
				});

				// SourceName, i=2045, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- BaseEventType/2041
				AddDefaultAddressSpaceNodeVariable(2045, "SourceName", "SourceName", "A description of the source of the event.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2041,  true),
				});

				// Time, i=2046, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- BaseEventType/2041
				AddDefaultAddressSpaceNodeVariable(2046, "Time", "Time", "When the event occurred.", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2041,  true),
				});

				// ReceiveTime, i=2047, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- BaseEventType/2041
				AddDefaultAddressSpaceNodeVariable(2047, "ReceiveTime", "ReceiveTime", "When the server received the event from the underlying system.", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2041,  true),
				});

				// LocalTime, i=3190, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- BaseEventType/2041
				AddDefaultAddressSpaceNodeVariable(3190, "LocalTime", "LocalTime", "Information about the local time where the event originated.", 0, 0, 0, 0, 0, false, 8912, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2041,  true),
				});

				// Message, i=2050, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- BaseEventType/2041
				AddDefaultAddressSpaceNodeVariable(2050, "Message", "Message", "A localized description of the event.", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2041,  true),
				});

				// Severity, i=2051, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- BaseEventType/2041
				AddDefaultAddressSpaceNodeVariable(2051, "Severity", "Severity", "Indicates how urgent an event is.", 0, 0, 0, 0, 0, false, 5, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2041,  true),
				});

				// ActionTimeStamp, i=2053, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditEventType/2052
				AddDefaultAddressSpaceNodeVariable(2053, "ActionTimeStamp", "ActionTimeStamp", "When the action triggering the event occurred.", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2052,  true),
				});

				// Status, i=2054, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditEventType/2052
				AddDefaultAddressSpaceNodeVariable(2054, "Status", "Status", "If TRUE the action was performed. If FALSE the action failed and the server state did not change.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2052,  true),
				});

				// ServerId, i=2055, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditEventType/2052
				AddDefaultAddressSpaceNodeVariable(2055, "ServerId", "ServerId", "The unique identifier for the server generating the event.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2052,  true),
				});

				// ClientAuditEntryId, i=2056, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditEventType/2052
				AddDefaultAddressSpaceNodeVariable(2056, "ClientAuditEntryId", "ClientAuditEntryId", "The log entry id provided in the request that initiated the action.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2052,  true),
				});

				// ClientUserId, i=2057, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditEventType/2052
				AddDefaultAddressSpaceNodeVariable(2057, "ClientUserId", "ClientUserId", "The user identity associated with the session that initiated the action.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2052,  true),
				});

				// SecureChannelId, i=2745, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditChannelEventType/2059
				AddDefaultAddressSpaceNodeVariable(2745, "SecureChannelId", "SecureChannelId", "The identifier for the secure channel that was changed.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2059,  true),
				});

				// ClientCertificate, i=2061, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditOpenSecureChannelEventType/2060
				AddDefaultAddressSpaceNodeVariable(2061, "ClientCertificate", "ClientCertificate", "The certificate provided by the client.", 0, 0, 0, 0, 0, false, 15, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2060,  true),
				});

				// ClientCertificateThumbprint, i=2746, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditOpenSecureChannelEventType/2060
				AddDefaultAddressSpaceNodeVariable(2746, "ClientCertificateThumbprint", "ClientCertificateThumbprint", "The thumbprint for certificate provided by the client.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2060,  true),
				});

				// RequestType, i=2062, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditOpenSecureChannelEventType/2060
				AddDefaultAddressSpaceNodeVariable(2062, "RequestType", "RequestType", "The type of request (NEW or RENEW).", 0, 0, 0, 0, 0, false, 315, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2060,  true),
				});

				// SecurityPolicyUri, i=2063, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditOpenSecureChannelEventType/2060
				AddDefaultAddressSpaceNodeVariable(2063, "SecurityPolicyUri", "SecurityPolicyUri", "The security policy used by the channel.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2060,  true),
				});

				// SecurityMode, i=2065, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditOpenSecureChannelEventType/2060
				AddDefaultAddressSpaceNodeVariable(2065, "SecurityMode", "SecurityMode", "The security mode used by the channel.", 0, 0, 0, 0, 0, false, 302, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2060,  true),
				});

				// RequestedLifetime, i=2066, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditOpenSecureChannelEventType/2060
				AddDefaultAddressSpaceNodeVariable(2066, "RequestedLifetime", "RequestedLifetime", "The lifetime of the channel requested by the client.", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2060,  true),
				});

				// SessionId, i=2070, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditSessionEventType/2069
				AddDefaultAddressSpaceNodeVariable(2070, "SessionId", "SessionId", "The unique identifier for the session,.", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2069,  true),
				});

				// SecureChannelId, i=2072, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditCreateSessionEventType/2071
				AddDefaultAddressSpaceNodeVariable(2072, "SecureChannelId", "SecureChannelId", "The secure channel associated with the session.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2071,  true),
				});

				// ClientCertificate, i=2073, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditCreateSessionEventType/2071
				AddDefaultAddressSpaceNodeVariable(2073, "ClientCertificate", "ClientCertificate", "The certificate provided by the client.", 0, 0, 0, 0, 0, false, 15, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2071,  true),
				});

				// ClientCertificateThumbprint, i=2747, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditCreateSessionEventType/2071
				AddDefaultAddressSpaceNodeVariable(2747, "ClientCertificateThumbprint", "ClientCertificateThumbprint", "The thumbprint of the certificate provided by the client.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2071,  true),
				});

				// RevisedSessionTimeout, i=2074, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditCreateSessionEventType/2071
				AddDefaultAddressSpaceNodeVariable(2074, "RevisedSessionTimeout", "RevisedSessionTimeout", "The timeout for the session.", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2071,  true),
				});

				// EndpointUrl, i=2749, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditUrlMismatchEventType/2748
				AddDefaultAddressSpaceNodeVariable(2749, "EndpointUrl", "EndpointUrl", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2748,  true),
				});

				// ClientSoftwareCertificates, i=2076, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditActivateSessionEventType/2075
				AddDefaultAddressSpaceNodeVariable(2076, "ClientSoftwareCertificates", "ClientSoftwareCertificates", "", 0, 0, 0, 0, 0, false, 344, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2075,  true),
				});

				// UserIdentityToken, i=2077, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditActivateSessionEventType/2075
				AddDefaultAddressSpaceNodeVariable(2077, "UserIdentityToken", "UserIdentityToken", "", 0, 0, 0, 0, 0, false, 316, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2075,  true),
				});

				// SecureChannelId, i=11485, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditActivateSessionEventType/2075
				AddDefaultAddressSpaceNodeVariable(11485, "SecureChannelId", "SecureChannelId", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2075,  true),
				});

				// RequestHandle, i=2079, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditCancelEventType/2078
				AddDefaultAddressSpaceNodeVariable(2079, "RequestHandle", "RequestHandle", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2078,  true),
				});

				// Certificate, i=2081, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditCertificateEventType/2080
				AddDefaultAddressSpaceNodeVariable(2081, "Certificate", "Certificate", "", 0, 0, 0, 0, 0, false, 15, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2080,  true),
				});

				// InvalidHostname, i=2083, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditCertificateDataMismatchEventType/2082
				AddDefaultAddressSpaceNodeVariable(2083, "InvalidHostname", "InvalidHostname", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2082,  true),
				});

				// InvalidUri, i=2084, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditCertificateDataMismatchEventType/2082
				AddDefaultAddressSpaceNodeVariable(2084, "InvalidUri", "InvalidUri", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2082,  true),
				});

				// NodesToAdd, i=2092, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditAddNodesEventType/2091
				AddDefaultAddressSpaceNodeVariable(2092, "NodesToAdd", "NodesToAdd", "", 0, 0, 0, 0, 0, false, 376, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2091,  true),
				});

				// NodesToDelete, i=2094, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditDeleteNodesEventType/2093
				AddDefaultAddressSpaceNodeVariable(2094, "NodesToDelete", "NodesToDelete", "", 0, 0, 0, 0, 0, false, 382, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2093,  true),
				});

				// ReferencesToAdd, i=2096, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditAddReferencesEventType/2095
				AddDefaultAddressSpaceNodeVariable(2096, "ReferencesToAdd", "ReferencesToAdd", "", 0, 0, 0, 0, 0, false, 379, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2095,  true),
				});

				// ReferencesToDelete, i=2098, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditDeleteReferencesEventType/2097
				AddDefaultAddressSpaceNodeVariable(2098, "ReferencesToDelete", "ReferencesToDelete", "", 0, 0, 0, 0, 0, false, 385, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2097,  true),
				});

				// AttributeId, i=2750, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditWriteUpdateEventType/2100
				AddDefaultAddressSpaceNodeVariable(2750, "AttributeId", "AttributeId", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2100,  true),
				});

				// IndexRange, i=2101, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditWriteUpdateEventType/2100
				AddDefaultAddressSpaceNodeVariable(2101, "IndexRange", "IndexRange", "", 0, 0, 0, 0, 0, false, 291, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2100,  true),
				});

				// OldValue, i=2102, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditWriteUpdateEventType/2100
				AddDefaultAddressSpaceNodeVariable(2102, "OldValue", "OldValue", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2100,  true),
				});

				// NewValue, i=2103, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditWriteUpdateEventType/2100
				AddDefaultAddressSpaceNodeVariable(2103, "NewValue", "NewValue", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2100,  true),
				});

				// ParameterDataTypeId, i=2751, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryUpdateEventType/2104
				AddDefaultAddressSpaceNodeVariable(2751, "ParameterDataTypeId", "ParameterDataTypeId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2104,  true),
				});

				// MethodId, i=2128, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditUpdateMethodEventType/2127
				AddDefaultAddressSpaceNodeVariable(2128, "MethodId", "MethodId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2127,  true),
				});

				// InputArguments, i=2129, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditUpdateMethodEventType/2127
				AddDefaultAddressSpaceNodeVariable(2129, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2127,  true),
				});

				// SystemState, i=11696, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- SystemStatusChangeEventType/11446
				AddDefaultAddressSpaceNodeVariable(11696, "SystemState", "SystemState", "", 0, 0, 0, 0, 0, false, 852, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11446,  true),
				});

				// Changes, i=2134, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- GeneralModelChangeEventType/2133
				AddDefaultAddressSpaceNodeVariable(2134, "Changes", "Changes", "", 0, 0, 0, 0, 0, false, 877, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2133,  true),
				});

				// Changes, i=2739, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- SemanticChangeEventType/2738
				AddDefaultAddressSpaceNodeVariable(2739, "Changes", "Changes", "", 0, 0, 0, 0, 0, false, 897, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2738,  true),
				});

				// StartTime, i=2139, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerStatusType/2138
				AddDefaultAddressSpaceNodeVariable(2139, "StartTime", "StartTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2138,  true),
				});

				// CurrentTime, i=2140, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerStatusType/2138
				AddDefaultAddressSpaceNodeVariable(2140, "CurrentTime", "CurrentTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2138,  true),
				});

			}
			private void Part10()
			{
				// State, i=2141, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerStatusType/2138
				AddDefaultAddressSpaceNodeVariable(2141, "State", "State", "", 0, 0, 0, 0, 0, false, 852, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2138,  true),
				});

				// BuildInfo, i=2142, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasComponent/47 -> ProductUri/3698
				//	HasComponent/47 -> ManufacturerName/3699
				//	HasComponent/47 -> ProductName/3700
				//	HasComponent/47 -> SoftwareVersion/3701
				//	HasComponent/47 -> BuildNumber/3702
				//	HasComponent/47 -> BuildDate/3703
				//	HasTypeDefinition/40 -> BuildInfoType/3051
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerStatusType/2138
				AddDefaultAddressSpaceNodeVariable(2142, "BuildInfo", "BuildInfo", "", 0, 0, 0, 0, 0, false, 338, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3698,  false),
					(47,  3699,  false),
					(47,  3700,  false),
					(47,  3701,  false),
					(47,  3702,  false),
					(47,  3703,  false),
					(40,  3051,  false),
					(37,  78,  false),
					(47,  2138,  true),
				});

				// ProductUri, i=3698, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfo/2142
				AddDefaultAddressSpaceNodeVariable(3698, "ProductUri", "ProductUri", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2142,  true),
				});

				// ManufacturerName, i=3699, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfo/2142
				AddDefaultAddressSpaceNodeVariable(3699, "ManufacturerName", "ManufacturerName", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2142,  true),
				});

				// ProductName, i=3700, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfo/2142
				AddDefaultAddressSpaceNodeVariable(3700, "ProductName", "ProductName", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2142,  true),
				});

				// SoftwareVersion, i=3701, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfo/2142
				AddDefaultAddressSpaceNodeVariable(3701, "SoftwareVersion", "SoftwareVersion", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2142,  true),
				});

				// BuildNumber, i=3702, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfo/2142
				AddDefaultAddressSpaceNodeVariable(3702, "BuildNumber", "BuildNumber", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2142,  true),
				});

				// BuildDate, i=3703, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfo/2142
				AddDefaultAddressSpaceNodeVariable(3703, "BuildDate", "BuildDate", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2142,  true),
				});

				// SecondsTillShutdown, i=2752, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerStatusType/2138
				AddDefaultAddressSpaceNodeVariable(2752, "SecondsTillShutdown", "SecondsTillShutdown", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2138,  true),
				});

				// ShutdownReason, i=2753, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerStatusType/2138
				AddDefaultAddressSpaceNodeVariable(2753, "ShutdownReason", "ShutdownReason", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2138,  true),
				});

				// ProductUri, i=3052, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfoType/3051
				AddDefaultAddressSpaceNodeVariable(3052, "ProductUri", "ProductUri", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3051,  true),
				});

				// ManufacturerName, i=3053, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfoType/3051
				AddDefaultAddressSpaceNodeVariable(3053, "ManufacturerName", "ManufacturerName", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3051,  true),
				});

				// ProductName, i=3054, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfoType/3051
				AddDefaultAddressSpaceNodeVariable(3054, "ProductName", "ProductName", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3051,  true),
				});

				// SoftwareVersion, i=3055, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfoType/3051
				AddDefaultAddressSpaceNodeVariable(3055, "SoftwareVersion", "SoftwareVersion", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3051,  true),
				});

				// BuildNumber, i=3056, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfoType/3051
				AddDefaultAddressSpaceNodeVariable(3056, "BuildNumber", "BuildNumber", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3051,  true),
				});

				// BuildDate, i=3057, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- BuildInfoType/3051
				AddDefaultAddressSpaceNodeVariable(3057, "BuildDate", "BuildDate", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  3051,  true),
				});

				// ServerViewCount, i=2151, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummaryType/2150
				AddDefaultAddressSpaceNodeVariable(2151, "ServerViewCount", "ServerViewCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2150,  true),
				});

				// CurrentSessionCount, i=2152, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummaryType/2150
				AddDefaultAddressSpaceNodeVariable(2152, "CurrentSessionCount", "CurrentSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2150,  true),
				});

				// CumulatedSessionCount, i=2153, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummaryType/2150
				AddDefaultAddressSpaceNodeVariable(2153, "CumulatedSessionCount", "CumulatedSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2150,  true),
				});

				// SecurityRejectedSessionCount, i=2154, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummaryType/2150
				AddDefaultAddressSpaceNodeVariable(2154, "SecurityRejectedSessionCount", "SecurityRejectedSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2150,  true),
				});

				// RejectedSessionCount, i=2155, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummaryType/2150
				AddDefaultAddressSpaceNodeVariable(2155, "RejectedSessionCount", "RejectedSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2150,  true),
				});

				// SessionTimeoutCount, i=2156, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummaryType/2150
				AddDefaultAddressSpaceNodeVariable(2156, "SessionTimeoutCount", "SessionTimeoutCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2150,  true),
				});

				// SessionAbortCount, i=2157, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummaryType/2150
				AddDefaultAddressSpaceNodeVariable(2157, "SessionAbortCount", "SessionAbortCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2150,  true),
				});

				// PublishingIntervalCount, i=2159, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummaryType/2150
				AddDefaultAddressSpaceNodeVariable(2159, "PublishingIntervalCount", "PublishingIntervalCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2150,  true),
				});

				// CurrentSubscriptionCount, i=2160, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummaryType/2150
				AddDefaultAddressSpaceNodeVariable(2160, "CurrentSubscriptionCount", "CurrentSubscriptionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2150,  true),
				});

				// CumulatedSubscriptionCount, i=2161, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummaryType/2150
				AddDefaultAddressSpaceNodeVariable(2161, "CumulatedSubscriptionCount", "CumulatedSubscriptionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2150,  true),
				});

				// SecurityRejectedRequestsCount, i=2162, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummaryType/2150
				AddDefaultAddressSpaceNodeVariable(2162, "SecurityRejectedRequestsCount", "SecurityRejectedRequestsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2150,  true),
				});

				// RejectedRequestsCount, i=2163, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ServerDiagnosticsSummaryType/2150
				AddDefaultAddressSpaceNodeVariable(2163, "RejectedRequestsCount", "RejectedRequestsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2150,  true),
				});

				// SamplingInterval, i=2166, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SamplingIntervalDiagnosticsType/2165
				AddDefaultAddressSpaceNodeVariable(2166, "SamplingInterval", "SamplingInterval", "", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2165,  true),
				});

				// SampledMonitoredItemsCount, i=11697, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SamplingIntervalDiagnosticsType/2165
				AddDefaultAddressSpaceNodeVariable(11697, "SampledMonitoredItemsCount", "SampledMonitoredItemsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2165,  true),
				});

				// MaxSampledMonitoredItemsCount, i=11698, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SamplingIntervalDiagnosticsType/2165
				AddDefaultAddressSpaceNodeVariable(11698, "MaxSampledMonitoredItemsCount", "MaxSampledMonitoredItemsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2165,  true),
				});

				// DisabledMonitoredItemsSamplingCount, i=11699, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SamplingIntervalDiagnosticsType/2165
				AddDefaultAddressSpaceNodeVariable(11699, "DisabledMonitoredItemsSamplingCount", "DisabledMonitoredItemsSamplingCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2165,  true),
				});

				// SessionId, i=2173, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2173, "SessionId", "SessionId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// SubscriptionId, i=2174, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2174, "SubscriptionId", "SubscriptionId", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// Priority, i=2175, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2175, "Priority", "Priority", "", 0, 0, 0, 0, 0, false, 3, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// PublishingInterval, i=2176, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2176, "PublishingInterval", "PublishingInterval", "", 0, 0, 0, 0, 0, false, 11, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// MaxKeepAliveCount, i=2177, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2177, "MaxKeepAliveCount", "MaxKeepAliveCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// MaxLifetimeCount, i=8888, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(8888, "MaxLifetimeCount", "MaxLifetimeCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// MaxNotificationsPerPublish, i=2179, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2179, "MaxNotificationsPerPublish", "MaxNotificationsPerPublish", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// PublishingEnabled, i=2180, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2180, "PublishingEnabled", "PublishingEnabled", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// ModifyCount, i=2181, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2181, "ModifyCount", "ModifyCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// EnableCount, i=2182, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2182, "EnableCount", "EnableCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// DisableCount, i=2183, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2183, "DisableCount", "DisableCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// RepublishRequestCount, i=2184, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2184, "RepublishRequestCount", "RepublishRequestCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// RepublishMessageRequestCount, i=2185, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2185, "RepublishMessageRequestCount", "RepublishMessageRequestCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// RepublishMessageCount, i=2186, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2186, "RepublishMessageCount", "RepublishMessageCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// TransferRequestCount, i=2187, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2187, "TransferRequestCount", "TransferRequestCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// TransferredToAltClientCount, i=2188, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2188, "TransferredToAltClientCount", "TransferredToAltClientCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// TransferredToSameClientCount, i=2189, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2189, "TransferredToSameClientCount", "TransferredToSameClientCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// PublishRequestCount, i=2190, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2190, "PublishRequestCount", "PublishRequestCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// DataChangeNotificationsCount, i=2191, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2191, "DataChangeNotificationsCount", "DataChangeNotificationsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// EventNotificationsCount, i=2998, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2998, "EventNotificationsCount", "EventNotificationsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// NotificationsCount, i=2193, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(2193, "NotificationsCount", "NotificationsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// LatePublishRequestCount, i=8889, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(8889, "LatePublishRequestCount", "LatePublishRequestCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// CurrentKeepAliveCount, i=8890, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(8890, "CurrentKeepAliveCount", "CurrentKeepAliveCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// CurrentLifetimeCount, i=8891, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(8891, "CurrentLifetimeCount", "CurrentLifetimeCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// UnacknowledgedMessageCount, i=8892, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(8892, "UnacknowledgedMessageCount", "UnacknowledgedMessageCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// DiscardedMessageCount, i=8893, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(8893, "DiscardedMessageCount", "DiscardedMessageCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// MonitoredItemCount, i=8894, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(8894, "MonitoredItemCount", "MonitoredItemCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// DisabledMonitoredItemCount, i=8895, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(8895, "DisabledMonitoredItemCount", "DisabledMonitoredItemCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// MonitoringQueueOverflowCount, i=8896, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(8896, "MonitoringQueueOverflowCount", "MonitoringQueueOverflowCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// NextSequenceNumber, i=8897, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(8897, "NextSequenceNumber", "NextSequenceNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// EventQueueOverFlowCount, i=8902, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SubscriptionDiagnosticsType/2172
				AddDefaultAddressSpaceNodeVariable(8902, "EventQueueOverFlowCount", "EventQueueOverFlowCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2172,  true),
				});

				// SessionId, i=2198, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2198, "SessionId", "SessionId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// SessionName, i=2199, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2199, "SessionName", "SessionName", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// ClientDescription, i=2200, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2200, "ClientDescription", "ClientDescription", "", 0, 0, 0, 0, 0, false, 308, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// ServerUri, i=2201, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2201, "ServerUri", "ServerUri", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// EndpointUrl, i=2202, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2202, "EndpointUrl", "EndpointUrl", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// LocaleIds, i=2203, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2203, "LocaleIds", "LocaleIds", "", 0, 0, 0, 0, 0, false, 295, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// ActualSessionTimeout, i=2204, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2204, "ActualSessionTimeout", "ActualSessionTimeout", "", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// MaxResponseMessageSize, i=3050, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(3050, "MaxResponseMessageSize", "MaxResponseMessageSize", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// ClientConnectionTime, i=2205, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2205, "ClientConnectionTime", "ClientConnectionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// ClientLastContactTime, i=2206, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2206, "ClientLastContactTime", "ClientLastContactTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// CurrentSubscriptionsCount, i=2207, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2207, "CurrentSubscriptionsCount", "CurrentSubscriptionsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// CurrentMonitoredItemsCount, i=2208, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2208, "CurrentMonitoredItemsCount", "CurrentMonitoredItemsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// CurrentPublishRequestsInQueue, i=2209, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2209, "CurrentPublishRequestsInQueue", "CurrentPublishRequestsInQueue", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// TotalRequestCount, i=8900, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(8900, "TotalRequestCount", "TotalRequestCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// UnauthorizedRequestCount, i=11892, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(11892, "UnauthorizedRequestCount", "UnauthorizedRequestCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// ReadCount, i=2217, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2217, "ReadCount", "ReadCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// HistoryReadCount, i=2218, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2218, "HistoryReadCount", "HistoryReadCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// WriteCount, i=2219, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2219, "WriteCount", "WriteCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// HistoryUpdateCount, i=2220, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2220, "HistoryUpdateCount", "HistoryUpdateCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// CallCount, i=2221, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2221, "CallCount", "CallCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// CreateMonitoredItemsCount, i=2222, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2222, "CreateMonitoredItemsCount", "CreateMonitoredItemsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// ModifyMonitoredItemsCount, i=2223, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2223, "ModifyMonitoredItemsCount", "ModifyMonitoredItemsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// SetMonitoringModeCount, i=2224, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2224, "SetMonitoringModeCount", "SetMonitoringModeCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// SetTriggeringCount, i=2225, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2225, "SetTriggeringCount", "SetTriggeringCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// DeleteMonitoredItemsCount, i=2226, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2226, "DeleteMonitoredItemsCount", "DeleteMonitoredItemsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// CreateSubscriptionCount, i=2227, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2227, "CreateSubscriptionCount", "CreateSubscriptionCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// ModifySubscriptionCount, i=2228, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2228, "ModifySubscriptionCount", "ModifySubscriptionCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// SetPublishingModeCount, i=2229, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2229, "SetPublishingModeCount", "SetPublishingModeCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// PublishCount, i=2230, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2230, "PublishCount", "PublishCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// RepublishCount, i=2231, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2231, "RepublishCount", "RepublishCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// TransferSubscriptionsCount, i=2232, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2232, "TransferSubscriptionsCount", "TransferSubscriptionsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// DeleteSubscriptionsCount, i=2233, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2233, "DeleteSubscriptionsCount", "DeleteSubscriptionsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// AddNodesCount, i=2234, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2234, "AddNodesCount", "AddNodesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// AddReferencesCount, i=2235, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2235, "AddReferencesCount", "AddReferencesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// DeleteNodesCount, i=2236, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2236, "DeleteNodesCount", "DeleteNodesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// DeleteReferencesCount, i=2237, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2237, "DeleteReferencesCount", "DeleteReferencesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});
			}
			private void Part11()
			{
				// BrowseCount, i=2238, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2238, "BrowseCount", "BrowseCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// BrowseNextCount, i=2239, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2239, "BrowseNextCount", "BrowseNextCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// TranslateBrowsePathsToNodeIdsCount, i=2240, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2240, "TranslateBrowsePathsToNodeIdsCount", "TranslateBrowsePathsToNodeIdsCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// QueryFirstCount, i=2241, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2241, "QueryFirstCount", "QueryFirstCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// QueryNextCount, i=2242, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2242, "QueryNextCount", "QueryNextCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// RegisterNodesCount, i=2730, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2730, "RegisterNodesCount", "RegisterNodesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// UnregisterNodesCount, i=2731, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionDiagnosticsVariableType/2197
				AddDefaultAddressSpaceNodeVariable(2731, "UnregisterNodesCount", "UnregisterNodesCount", "", 0, 0, 0, 0, 0, false, 871, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2197,  true),
				});

				// SessionId, i=2245, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnosticsType/2244
				AddDefaultAddressSpaceNodeVariable(2245, "SessionId", "SessionId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2244,  true),
				});

				// ClientUserIdOfSession, i=2246, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnosticsType/2244
				AddDefaultAddressSpaceNodeVariable(2246, "ClientUserIdOfSession", "ClientUserIdOfSession", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2244,  true),
				});

				// ClientUserIdHistory, i=2247, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnosticsType/2244
				AddDefaultAddressSpaceNodeVariable(2247, "ClientUserIdHistory", "ClientUserIdHistory", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2244,  true),
				});

				// AuthenticationMechanism, i=2248, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnosticsType/2244
				AddDefaultAddressSpaceNodeVariable(2248, "AuthenticationMechanism", "AuthenticationMechanism", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2244,  true),
				});

				// Encoding, i=2249, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnosticsType/2244
				AddDefaultAddressSpaceNodeVariable(2249, "Encoding", "Encoding", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2244,  true),
				});

				// TransportProtocol, i=2250, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnosticsType/2244
				AddDefaultAddressSpaceNodeVariable(2250, "TransportProtocol", "TransportProtocol", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2244,  true),
				});

				// SecurityMode, i=2251, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnosticsType/2244
				AddDefaultAddressSpaceNodeVariable(2251, "SecurityMode", "SecurityMode", "", 0, 0, 0, 0, 0, false, 302, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2244,  true),
				});

				// SecurityPolicyUri, i=2252, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnosticsType/2244
				AddDefaultAddressSpaceNodeVariable(2252, "SecurityPolicyUri", "SecurityPolicyUri", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2244,  true),
				});

				// ClientCertificate, i=3058, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- SessionSecurityDiagnosticsType/2244
				AddDefaultAddressSpaceNodeVariable(3058, "ClientCertificate", "ClientCertificate", "", 0, 0, 0, 0, 0, false, 15, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(37,  78,  false),
					(47,  2244,  true),
				});

				// OptionSetValues, i=11488, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- OptionSetType/11487
				AddDefaultAddressSpaceNodeVariable(11488, "OptionSetValues", "OptionSetValues", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11487,  true),
				});

				// BitMask, i=11701, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- OptionSetType/11487
				AddDefaultAddressSpaceNodeVariable(11701, "BitMask", "BitMask", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  11487,  true),
				});

				// ServerArray, i=2254, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- Server/2253
				AddDefaultAddressSpaceNodeVariable(2254, "ServerArray", "ServerArray", "The list of server URIs used by the server.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2253,  true),
				});

				// NamespaceArray, i=2255, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- Server/2253
				AddDefaultAddressSpaceNodeVariable(2255, "NamespaceArray", "NamespaceArray", "The list of namespace URIs used by the server.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2253,  true),
				});

				// ServerStatus, i=2256, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasComponent/47 -> StartTime/2257
				//	HasComponent/47 -> CurrentTime/2258
				//	HasComponent/47 -> State/2259
				//	HasComponent/47 -> BuildInfo/2260
				//	HasComponent/47 -> SecondsTillShutdown/2992
				//	HasComponent/47 -> ShutdownReason/2993
				//	HasTypeDefinition/40 -> ServerStatusType/2138
				//	HasComponent/47 <- Server/2253
				AddDefaultAddressSpaceNodeVariable(2256, "ServerStatus", "ServerStatus", "The current status of the server.", 0, 0, 0, 0, 0, false, 862, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2257,  false),
					(47,  2258,  false),
					(47,  2259,  false),
					(47,  2260,  false),
					(47,  2992,  false),
					(47,  2993,  false),
					(40,  2138,  false),
					(47,  2253,  true),
				});

				// StartTime, i=2257, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerStatus/2256
				AddDefaultAddressSpaceNodeVariable(2257, "StartTime", "StartTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2256,  true),
				});

				// CurrentTime, i=2258, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerStatus/2256
				AddDefaultAddressSpaceNodeVariable(2258, "CurrentTime", "CurrentTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2256,  true),
				});

				// State, i=2259, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerStatus/2256
				AddDefaultAddressSpaceNodeVariable(2259, "State", "State", "", 0, 0, 0, 0, 0, false, 852, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2256,  true),
				});

				// BuildInfo, i=2260, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasComponent/47 -> ProductUri/2262
				//	HasComponent/47 -> ManufacturerName/2263
				//	HasComponent/47 -> ProductName/2261
				//	HasComponent/47 -> SoftwareVersion/2264
				//	HasComponent/47 -> BuildNumber/2265
				//	HasComponent/47 -> BuildDate/2266
				//	HasTypeDefinition/40 -> BuildInfoType/3051
				//	HasComponent/47 <- ServerStatus/2256
				AddDefaultAddressSpaceNodeVariable(2260, "BuildInfo", "BuildInfo", "", 0, 0, 0, 0, 0, false, 338, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2262,  false),
					(47,  2263,  false),
					(47,  2261,  false),
					(47,  2264,  false),
					(47,  2265,  false),
					(47,  2266,  false),
					(40,  3051,  false),
					(47,  2256,  true),
				});

				// ProductUri, i=2262, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- BuildInfo/2260
				AddDefaultAddressSpaceNodeVariable(2262, "ProductUri", "ProductUri", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2260,  true),
				});

				// ManufacturerName, i=2263, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- BuildInfo/2260
				AddDefaultAddressSpaceNodeVariable(2263, "ManufacturerName", "ManufacturerName", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2260,  true),
				});

				// ProductName, i=2261, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- BuildInfo/2260
				AddDefaultAddressSpaceNodeVariable(2261, "ProductName", "ProductName", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2260,  true),
				});

				// SoftwareVersion, i=2264, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- BuildInfo/2260
				AddDefaultAddressSpaceNodeVariable(2264, "SoftwareVersion", "SoftwareVersion", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2260,  true),
				});

				// BuildNumber, i=2265, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- BuildInfo/2260
				AddDefaultAddressSpaceNodeVariable(2265, "BuildNumber", "BuildNumber", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2260,  true),
				});

				// BuildDate, i=2266, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- BuildInfo/2260
				AddDefaultAddressSpaceNodeVariable(2266, "BuildDate", "BuildDate", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2260,  true),
				});

				// SecondsTillShutdown, i=2992, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerStatus/2256
				AddDefaultAddressSpaceNodeVariable(2992, "SecondsTillShutdown", "SecondsTillShutdown", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2256,  true),
				});

				// ShutdownReason, i=2993, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerStatus/2256
				AddDefaultAddressSpaceNodeVariable(2993, "ShutdownReason", "ShutdownReason", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2256,  true),
				});

				// ServiceLevel, i=2267, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- Server/2253
				AddDefaultAddressSpaceNodeVariable(2267, "ServiceLevel", "ServiceLevel", "A value indicating the level of service the server can provide. 255 indicates the best.", 0, 0, 0, 0, 0, false, 3, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2253,  true),
				});

				// Auditing, i=2994, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- Server/2253
				AddDefaultAddressSpaceNodeVariable(2994, "Auditing", "Auditing", "A flag indicating whether the server is currently generating audit events.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2253,  true),
				});

				// ServerProfileArray, i=2269, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ServerCapabilities/2268
				AddDefaultAddressSpaceNodeVariable(2269, "ServerProfileArray", "ServerProfileArray", "A list of profiles supported by the server.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2268,  true),
				});

				// LocaleIdArray, i=2271, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ServerCapabilities/2268
				AddDefaultAddressSpaceNodeVariable(2271, "LocaleIdArray", "LocaleIdArray", "A list of locales supported by the server.", 0, 0, 0, 0, 0, false, 295, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2268,  true),
				});

				// MinSupportedSampleRate, i=2272, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ServerCapabilities/2268
				AddDefaultAddressSpaceNodeVariable(2272, "MinSupportedSampleRate", "MinSupportedSampleRate", "The minimum sampling interval supported by the server.", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2268,  true),
				});

				// MaxBrowseContinuationPoints, i=2735, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ServerCapabilities/2268
				AddDefaultAddressSpaceNodeVariable(2735, "MaxBrowseContinuationPoints", "MaxBrowseContinuationPoints", "The maximum number of continuation points for Browse operations per session.", 0, 0, 0, 0, 0, false, 5, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2268,  true),
				});

				// MaxQueryContinuationPoints, i=2736, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ServerCapabilities/2268
				AddDefaultAddressSpaceNodeVariable(2736, "MaxQueryContinuationPoints", "MaxQueryContinuationPoints", "The maximum number of continuation points for Query operations per session.", 0, 0, 0, 0, 0, false, 5, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2268,  true),
				});

				// MaxHistoryContinuationPoints, i=2737, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ServerCapabilities/2268
				AddDefaultAddressSpaceNodeVariable(2737, "MaxHistoryContinuationPoints", "MaxHistoryContinuationPoints", "The maximum number of continuation points for ReadHistory operations per session.", 0, 0, 0, 0, 0, false, 5, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2268,  true),
				});

				// SoftwareCertificates, i=3704, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ServerCapabilities/2268
				AddDefaultAddressSpaceNodeVariable(3704, "SoftwareCertificates", "SoftwareCertificates", "The software certificates owned by the server.", 0, 0, 0, 0, 0, false, 344, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2268,  true),
				});

				// MaxArrayLength, i=11702, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ServerCapabilities/2268
				AddDefaultAddressSpaceNodeVariable(11702, "MaxArrayLength", "MaxArrayLength", "The maximum length for an array value supported by the server.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2268,  true),
				});

				// MaxStringLength, i=11703, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ServerCapabilities/2268
				AddDefaultAddressSpaceNodeVariable(11703, "MaxStringLength", "MaxStringLength", "The maximum length for a string value supported by the server.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2268,  true),
				});

				// MaxNodesPerRead, i=11705, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- OperationLimits/11704
				AddDefaultAddressSpaceNodeVariable(11705, "MaxNodesPerRead", "MaxNodesPerRead", "The maximum number of operations in a single Read request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11704,  true),
				});

				// MaxNodesPerHistoryReadData, i=12165, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- OperationLimits/11704
				AddDefaultAddressSpaceNodeVariable(12165, "MaxNodesPerHistoryReadData", "MaxNodesPerHistoryReadData", "The maximum number of operations in a single data HistoryRead request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11704,  true),
				});

				// MaxNodesPerHistoryReadEvents, i=12166, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- OperationLimits/11704
				AddDefaultAddressSpaceNodeVariable(12166, "MaxNodesPerHistoryReadEvents", "MaxNodesPerHistoryReadEvents", "The maximum number of operations in a single event HistoryRead request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11704,  true),
				});

				// MaxNodesPerWrite, i=11707, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- OperationLimits/11704
				AddDefaultAddressSpaceNodeVariable(11707, "MaxNodesPerWrite", "MaxNodesPerWrite", "The maximum number of operations in a single Write request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11704,  true),
				});

				// MaxNodesPerHistoryUpdateData, i=12167, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- OperationLimits/11704
				AddDefaultAddressSpaceNodeVariable(12167, "MaxNodesPerHistoryUpdateData", "MaxNodesPerHistoryUpdateData", "The maximum number of operations in a single data HistoryUpdate request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11704,  true),
				});

				// MaxNodesPerHistoryUpdateEvents, i=12168, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- OperationLimits/11704
				AddDefaultAddressSpaceNodeVariable(12168, "MaxNodesPerHistoryUpdateEvents", "MaxNodesPerHistoryUpdateEvents", "The maximum number of operations in a single event HistoryUpdate request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11704,  true),
				});

				// MaxNodesPerMethodCall, i=11709, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- OperationLimits/11704
				AddDefaultAddressSpaceNodeVariable(11709, "MaxNodesPerMethodCall", "MaxNodesPerMethodCall", "The maximum number of operations in a single Call request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11704,  true),
				});

				// MaxNodesPerBrowse, i=11710, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- OperationLimits/11704
				AddDefaultAddressSpaceNodeVariable(11710, "MaxNodesPerBrowse", "MaxNodesPerBrowse", "The maximum number of operations in a single Browse request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11704,  true),
				});

				// MaxNodesPerRegisterNodes, i=11711, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- OperationLimits/11704
				AddDefaultAddressSpaceNodeVariable(11711, "MaxNodesPerRegisterNodes", "MaxNodesPerRegisterNodes", "The maximum number of operations in a single RegisterNodes request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11704,  true),
				});

				// MaxNodesPerTranslateBrowsePathsToNodeIds, i=11712, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- OperationLimits/11704
				AddDefaultAddressSpaceNodeVariable(11712, "MaxNodesPerTranslateBrowsePathsToNodeIds", "MaxNodesPerTranslateBrowsePathsToNodeIds", "The maximum number of operations in a single TranslateBrowsePathsToNodeIds request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11704,  true),
				});

				// MaxNodesPerNodeManagement, i=11713, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- OperationLimits/11704
				AddDefaultAddressSpaceNodeVariable(11713, "MaxNodesPerNodeManagement", "MaxNodesPerNodeManagement", "The maximum number of operations in a single AddNodes, AddReferences, DeleteNodes or DeleteReferences request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11704,  true),
				});

				// MaxMonitoredItemsPerCall, i=11714, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- OperationLimits/11704
				AddDefaultAddressSpaceNodeVariable(11714, "MaxMonitoredItemsPerCall", "MaxMonitoredItemsPerCall", "The maximum number of operations in a single MonitoredItem related request.", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11704,  true),
				});

				// ServerDiagnosticsSummary, i=2275, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasComponent/47 -> ServerViewCount/2276
				//	HasComponent/47 -> CurrentSessionCount/2277
				//	HasComponent/47 -> CumulatedSessionCount/2278
				//	HasComponent/47 -> SecurityRejectedSessionCount/2279
				//	HasComponent/47 -> RejectedSessionCount/3705
				//	HasComponent/47 -> SessionTimeoutCount/2281
				//	HasComponent/47 -> SessionAbortCount/2282
				//	HasComponent/47 -> PublishingIntervalCount/2284
				//	HasComponent/47 -> CurrentSubscriptionCount/2285
				//	HasComponent/47 -> CumulatedSubscriptionCount/2286
				//	HasComponent/47 -> SecurityRejectedRequestsCount/2287
				//	HasComponent/47 -> RejectedRequestsCount/2288
				//	HasTypeDefinition/40 -> ServerDiagnosticsSummaryType/2150
				//	HasComponent/47 <- ServerDiagnostics/2274
				AddDefaultAddressSpaceNodeVariable(2275, "ServerDiagnosticsSummary", "ServerDiagnosticsSummary", "A summary of server level diagnostics.", 0, 0, 0, 0, 0, false, 859, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2276,  false),
					(47,  2277,  false),
					(47,  2278,  false),
					(47,  2279,  false),
					(47,  3705,  false),
					(47,  2281,  false),
					(47,  2282,  false),
					(47,  2284,  false),
					(47,  2285,  false),
					(47,  2286,  false),
					(47,  2287,  false),
					(47,  2288,  false),
					(40,  2150,  false),
					(47,  2274,  true),
				});

				// ServerViewCount, i=2276, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerDiagnosticsSummary/2275
				AddDefaultAddressSpaceNodeVariable(2276, "ServerViewCount", "ServerViewCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2275,  true),
				});

				// CurrentSessionCount, i=2277, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerDiagnosticsSummary/2275
				AddDefaultAddressSpaceNodeVariable(2277, "CurrentSessionCount", "CurrentSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2275,  true),
				});

				// CumulatedSessionCount, i=2278, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerDiagnosticsSummary/2275
				AddDefaultAddressSpaceNodeVariable(2278, "CumulatedSessionCount", "CumulatedSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2275,  true),
				});

				// SecurityRejectedSessionCount, i=2279, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerDiagnosticsSummary/2275
				AddDefaultAddressSpaceNodeVariable(2279, "SecurityRejectedSessionCount", "SecurityRejectedSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2275,  true),
				});

				// RejectedSessionCount, i=3705, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerDiagnosticsSummary/2275
				AddDefaultAddressSpaceNodeVariable(3705, "RejectedSessionCount", "RejectedSessionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2275,  true),
				});

				// SessionTimeoutCount, i=2281, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerDiagnosticsSummary/2275
				AddDefaultAddressSpaceNodeVariable(2281, "SessionTimeoutCount", "SessionTimeoutCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2275,  true),
				});

				// SessionAbortCount, i=2282, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerDiagnosticsSummary/2275
				AddDefaultAddressSpaceNodeVariable(2282, "SessionAbortCount", "SessionAbortCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2275,  true),
				});

				// PublishingIntervalCount, i=2284, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerDiagnosticsSummary/2275
				AddDefaultAddressSpaceNodeVariable(2284, "PublishingIntervalCount", "PublishingIntervalCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2275,  true),
				});

				// CurrentSubscriptionCount, i=2285, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerDiagnosticsSummary/2275
				AddDefaultAddressSpaceNodeVariable(2285, "CurrentSubscriptionCount", "CurrentSubscriptionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2275,  true),
				});

				// CumulatedSubscriptionCount, i=2286, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerDiagnosticsSummary/2275
				AddDefaultAddressSpaceNodeVariable(2286, "CumulatedSubscriptionCount", "CumulatedSubscriptionCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2275,  true),
				});

				// SecurityRejectedRequestsCount, i=2287, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerDiagnosticsSummary/2275
				AddDefaultAddressSpaceNodeVariable(2287, "SecurityRejectedRequestsCount", "SecurityRejectedRequestsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2275,  true),
				});

				// RejectedRequestsCount, i=2288, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> BaseDataVariableType/63
				//	HasComponent/47 <- ServerDiagnosticsSummary/2275
				AddDefaultAddressSpaceNodeVariable(2288, "RejectedRequestsCount", "RejectedRequestsCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  63,  false),
					(47,  2275,  true),
				});

				// SamplingIntervalDiagnosticsArray, i=2289, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SamplingIntervalDiagnosticsArrayType/2164
				//	HasComponent/47 <- ServerDiagnostics/2274
				AddDefaultAddressSpaceNodeVariable(2289, "SamplingIntervalDiagnosticsArray", "SamplingIntervalDiagnosticsArray", "A list of diagnostics for each sampling interval supported by the server.", 0, 0, 0, 0, 0, false, 856, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2164,  false),
					(47,  2274,  true),
				});

				// SubscriptionDiagnosticsArray, i=2290, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SubscriptionDiagnosticsArrayType/2171
				//	HasComponent/47 <- ServerDiagnostics/2274
				AddDefaultAddressSpaceNodeVariable(2290, "SubscriptionDiagnosticsArray", "SubscriptionDiagnosticsArray", "A list of diagnostics for each active subscription.", 0, 0, 0, 0, 0, false, 874, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2171,  false),
					(47,  2274,  true),
				});

				// SessionDiagnosticsArray, i=3707, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SessionDiagnosticsArrayType/2196
				//	HasComponent/47 <- SessionsDiagnosticsSummary/3706
				AddDefaultAddressSpaceNodeVariable(3707, "SessionDiagnosticsArray", "SessionDiagnosticsArray", "A list of diagnostics for each active session.", 0, 0, 0, 0, 0, false, 865, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2196,  false),
					(47,  3706,  true),
				});

				// SessionSecurityDiagnosticsArray, i=3708, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> SessionSecurityDiagnosticsArrayType/2243
				//	HasComponent/47 <- SessionsDiagnosticsSummary/3706
				AddDefaultAddressSpaceNodeVariable(3708, "SessionSecurityDiagnosticsArray", "SessionSecurityDiagnosticsArray", "A list of security related diagnostics for each active session.", 0, 0, 0, 0, 0, false, 868, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  2243,  false),
					(47,  3706,  true),
				});

				// EnabledFlag, i=2294, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ServerDiagnostics/2274
				AddDefaultAddressSpaceNodeVariable(2294, "EnabledFlag", "EnabledFlag", "If TRUE the diagnostics collection is enabled.", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2274,  true),
				});

				// RedundancySupport, i=3709, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ServerRedundancy/2296
				AddDefaultAddressSpaceNodeVariable(3709, "RedundancySupport", "RedundancySupport", "Indicates what style of redundancy is supported by the server.", 0, 0, 0, 0, 0, false, 851, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2296,  true),
				});

				// CurrentServerId, i=11312, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ServerRedundancy/2296
				AddDefaultAddressSpaceNodeVariable(11312, "CurrentServerId", "CurrentServerId", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2296,  true),
				});

				// RedundantServerArray, i=11313, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ServerRedundancy/2296
				AddDefaultAddressSpaceNodeVariable(11313, "RedundantServerArray", "RedundantServerArray", "", 0, 0, 0, 0, 0, false, 853, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2296,  true),
				});

				// ServerUriArray, i=11314, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ServerRedundancy/2296
				AddDefaultAddressSpaceNodeVariable(11314, "ServerUriArray", "ServerUriArray", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2296,  true),
				});

				// InputArguments, i=11493, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- GetMonitoredItems/11492
				AddDefaultAddressSpaceNodeVariable(11493, "InputArguments", "InputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11492,  true),
				});

				// OutputArguments, i=11494, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- GetMonitoredItems/11492
				AddDefaultAddressSpaceNodeVariable(11494, "OutputArguments", "OutputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11492,  true),
				});

				// AccessHistoryDataCapability, i=11193, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeVariable(11193, "AccessHistoryDataCapability", "AccessHistoryDataCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11192,  true),
				});

				// AccessHistoryEventsCapability, i=11242, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeVariable(11242, "AccessHistoryEventsCapability", "AccessHistoryEventsCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11192,  true),
				});

				// MaxReturnDataValues, i=11273, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeVariable(11273, "MaxReturnDataValues", "MaxReturnDataValues", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11192,  true),
				});

				// MaxReturnEventValues, i=11274, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeVariable(11274, "MaxReturnEventValues", "MaxReturnEventValues", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11192,  true),
				});

				// InsertDataCapability, i=11196, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeVariable(11196, "InsertDataCapability", "InsertDataCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11192,  true),
				});

				// ReplaceDataCapability, i=11197, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeVariable(11197, "ReplaceDataCapability", "ReplaceDataCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11192,  true),
				});

				// UpdateDataCapability, i=11198, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeVariable(11198, "UpdateDataCapability", "UpdateDataCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11192,  true),
				});

				// DeleteRawCapability, i=11199, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeVariable(11199, "DeleteRawCapability", "DeleteRawCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11192,  true),
				});

				// DeleteAtTimeCapability, i=11200, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeVariable(11200, "DeleteAtTimeCapability", "DeleteAtTimeCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11192,  true),
				});

				// InsertEventCapability, i=11281, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeVariable(11281, "InsertEventCapability", "InsertEventCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11192,  true),
				});

				// ReplaceEventCapability, i=11282, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeVariable(11282, "ReplaceEventCapability", "ReplaceEventCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11192,  true),
				});

				// UpdateEventCapability, i=11283, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeVariable(11283, "UpdateEventCapability", "UpdateEventCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11192,  true),
				});

				// DeleteEventCapability, i=11502, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeVariable(11502, "DeleteEventCapability", "DeleteEventCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11192,  true),
				});

				// InsertAnnotationCapability, i=11275, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HistoryServerCapabilities/11192
				AddDefaultAddressSpaceNodeVariable(11275, "InsertAnnotationCapability", "InsertAnnotationCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11192,  true),
				});

				// CurrentState, i=2769, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/3720
				//	HasTypeDefinition/40 -> StateVariableType/2755
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- StateMachineType/2299
				AddDefaultAddressSpaceNodeVariable(2769, "CurrentState", "CurrentState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3720,  false),
					(40,  2755,  false),
					(37,  78,  false),
					(47,  2299,  true),
				});

				// Id, i=3720, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- CurrentState/2769
				AddDefaultAddressSpaceNodeVariable(3720, "Id", "Id", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2769,  true),
				});

				// LastTransition, i=2770, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/3724
				//	HasTypeDefinition/40 -> TransitionVariableType/2762
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- StateMachineType/2299
				AddDefaultAddressSpaceNodeVariable(2770, "LastTransition", "LastTransition", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3724,  false),
					(40,  2762,  false),
					(37,  80,  false),
					(47,  2299,  true),
				});

				// Id, i=3724, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- LastTransition/2770
				AddDefaultAddressSpaceNodeVariable(3724, "Id", "Id", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2770,  true),
				});

				// Id, i=2756, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- StateVariableType/2755
				AddDefaultAddressSpaceNodeVariable(2756, "Id", "Id", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2755,  true),
				});

				// Name, i=2757, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- StateVariableType/2755
				AddDefaultAddressSpaceNodeVariable(2757, "Name", "Name", "", 0, 0, 0, 0, 0, false, 20, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2755,  true),
				});

				// Number, i=2758, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- StateVariableType/2755
				AddDefaultAddressSpaceNodeVariable(2758, "Number", "Number", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2755,  true),
				});

				// EffectiveDisplayName, i=2759, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- StateVariableType/2755
				AddDefaultAddressSpaceNodeVariable(2759, "EffectiveDisplayName", "EffectiveDisplayName", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2755,  true),
				});

				// Id, i=2763, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- TransitionVariableType/2762
				AddDefaultAddressSpaceNodeVariable(2763, "Id", "Id", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2762,  true),
				});

				// Name, i=2764, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- TransitionVariableType/2762
				AddDefaultAddressSpaceNodeVariable(2764, "Name", "Name", "", 0, 0, 0, 0, 0, false, 20, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2762,  true),
				});

				// Number, i=2765, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- TransitionVariableType/2762
				AddDefaultAddressSpaceNodeVariable(2765, "Number", "Number", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2762,  true),
				});

				// TransitionTime, i=2766, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- TransitionVariableType/2762
				AddDefaultAddressSpaceNodeVariable(2766, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2762,  true),
				});

				// EffectiveTransitionTime, i=11456, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- TransitionVariableType/2762
				AddDefaultAddressSpaceNodeVariable(11456, "EffectiveTransitionTime", "EffectiveTransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2762,  true),
				});

				// CurrentState, i=2772, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/3728
				//	HasTypeDefinition/40 -> FiniteStateVariableType/2760
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- FiniteStateMachineType/2771
				AddDefaultAddressSpaceNodeVariable(2772, "CurrentState", "CurrentState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3728,  false),
					(40,  2760,  false),
					(37,  78,  false),
					(47,  2771,  true),
				});

				// Id, i=3728, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- CurrentState/2772
				AddDefaultAddressSpaceNodeVariable(3728, "Id", "Id", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2772,  true),
				});

				// LastTransition, i=2773, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/3732
				//	HasTypeDefinition/40 -> FiniteTransitionVariableType/2767
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- FiniteStateMachineType/2771
				AddDefaultAddressSpaceNodeVariable(2773, "LastTransition", "LastTransition", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3732,  false),
					(40,  2767,  false),
					(37,  80,  false),
					(47,  2771,  true),
				});


			}
			private void Part12()
			{
				// Id, i=3732, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- LastTransition/2773
				AddDefaultAddressSpaceNodeVariable(3732, "Id", "Id", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2773,  true),
				});

				// Id, i=2761, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- FiniteStateVariableType/2760
				AddDefaultAddressSpaceNodeVariable(2761, "Id", "Id", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2760,  true),
				});

				// Id, i=2768, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- FiniteTransitionVariableType/2767
				AddDefaultAddressSpaceNodeVariable(2768, "Id", "Id", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2767,  true),
				});

				// StateNumber, i=2308, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- StateType/2307
				AddDefaultAddressSpaceNodeVariable(2308, "StateNumber", "StateNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2307,  true),
				});

				// TransitionNumber, i=2312, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- TransitionType/2310
				AddDefaultAddressSpaceNodeVariable(2312, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2310,  true),
				});

				// Transition, i=2774, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/3754
				//	HasTypeDefinition/40 -> TransitionVariableType/2762
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- TransitionEventType/2311
				AddDefaultAddressSpaceNodeVariable(2774, "Transition", "Transition", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3754,  false),
					(40,  2762,  false),
					(37,  78,  false),
					(47,  2311,  true),
				});

				// Id, i=3754, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Transition/2774
				AddDefaultAddressSpaceNodeVariable(3754, "Id", "Id", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2774,  true),
				});

				// FromState, i=2775, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/3746
				//	HasTypeDefinition/40 -> StateVariableType/2755
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- TransitionEventType/2311
				AddDefaultAddressSpaceNodeVariable(2775, "FromState", "FromState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3746,  false),
					(40,  2755,  false),
					(37,  78,  false),
					(47,  2311,  true),
				});

				// Id, i=3746, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- FromState/2775
				AddDefaultAddressSpaceNodeVariable(3746, "Id", "Id", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2775,  true),
				});

				// ToState, i=2776, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/3750
				//	HasTypeDefinition/40 -> StateVariableType/2755
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- TransitionEventType/2311
				AddDefaultAddressSpaceNodeVariable(2776, "ToState", "ToState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3750,  false),
					(40,  2755,  false),
					(37,  78,  false),
					(47,  2311,  true),
				});

				// Id, i=3750, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ToState/2776
				AddDefaultAddressSpaceNodeVariable(3750, "Id", "Id", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2776,  true),
				});

				// OldStateId, i=2777, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditUpdateStateEventType/2315
				AddDefaultAddressSpaceNodeVariable(2777, "OldStateId", "OldStateId", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2315,  true),
				});

				// NewStateId, i=2778, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditUpdateStateEventType/2315
				AddDefaultAddressSpaceNodeVariable(2778, "NewStateId", "NewStateId", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2315,  true),
				});

				// EnumValues, i=11940, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- OpenFileMode/11939
				AddDefaultAddressSpaceNodeVariable(11940, "EnumValues", "EnumValues", "", 0, 0, 0, 0, 0, false, 7594, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11939,  true),
				});

				// Definition, i=2366, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- DataItemType/2365
				AddDefaultAddressSpaceNodeVariable(2366, "Definition", "Definition", "A vendor-specific, human readable string that specifies how the value of this DataItem is calculated.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2365,  true),
				});

				// ValuePrecision, i=2367, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- DataItemType/2365
				AddDefaultAddressSpaceNodeVariable(2367, "ValuePrecision", "ValuePrecision", "The maximum precision that the server can maintain for the item based on restrictions in the target environment.", 0, 0, 0, 0, 0, false, 11, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2365,  true),
				});

				// InstrumentRange, i=2370, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- AnalogItemType/2368
				AddDefaultAddressSpaceNodeVariable(2370, "InstrumentRange", "InstrumentRange", "", 0, 0, 0, 0, 0, false, 884, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2368,  true),
				});

				// EURange, i=2369, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AnalogItemType/2368
				AddDefaultAddressSpaceNodeVariable(2369, "EURange", "EURange", "", 0, 0, 0, 0, 0, false, 884, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2368,  true),
				});

				// EngineeringUnits, i=2371, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- AnalogItemType/2368
				AddDefaultAddressSpaceNodeVariable(2371, "EngineeringUnits", "EngineeringUnits", "", 0, 0, 0, 0, 0, false, 887, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2368,  true),
				});

				// FalseState, i=2374, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- TwoStateDiscreteType/2373
				AddDefaultAddressSpaceNodeVariable(2374, "FalseState", "FalseState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2373,  true),
				});

				// TrueState, i=2375, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- TwoStateDiscreteType/2373
				AddDefaultAddressSpaceNodeVariable(2375, "TrueState", "TrueState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2373,  true),
				});

				// EnumStrings, i=2377, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- MultiStateDiscreteType/2376
				AddDefaultAddressSpaceNodeVariable(2377, "EnumStrings", "EnumStrings", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2376,  true),
				});

				// EnumValues, i=11241, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- MultiStateValueDiscreteType/11238
				AddDefaultAddressSpaceNodeVariable(11241, "EnumValues", "EnumValues", "", 0, 0, 0, 0, 0, false, 7594, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11238,  true),
				});

				// ValueAsText, i=11461, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- MultiStateValueDiscreteType/11238
				AddDefaultAddressSpaceNodeVariable(11461, "ValueAsText", "ValueAsText", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11238,  true),
				});

				// InstrumentRange, i=12024, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- ArrayItemType/12021
				AddDefaultAddressSpaceNodeVariable(12024, "InstrumentRange", "InstrumentRange", "", 0, 0, 0, 0, 0, false, 884, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  12021,  true),
				});

				// EURange, i=12025, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ArrayItemType/12021
				AddDefaultAddressSpaceNodeVariable(12025, "EURange", "EURange", "", 0, 0, 0, 0, 0, false, 884, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  12021,  true),
				});

				// EngineeringUnits, i=12026, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ArrayItemType/12021
				AddDefaultAddressSpaceNodeVariable(12026, "EngineeringUnits", "EngineeringUnits", "", 0, 0, 0, 0, 0, false, 887, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  12021,  true),
				});

				// Title, i=12027, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ArrayItemType/12021
				AddDefaultAddressSpaceNodeVariable(12027, "Title", "Title", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  12021,  true),
				});

				// AxisScaleType, i=12028, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ArrayItemType/12021
				AddDefaultAddressSpaceNodeVariable(12028, "AxisScaleType", "AxisScaleType", "", 0, 0, 0, 0, 0, false, 12077, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  12021,  true),
				});

				// XAxisDefinition, i=12037, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- YArrayItemType/12029
				AddDefaultAddressSpaceNodeVariable(12037, "XAxisDefinition", "XAxisDefinition", "", 0, 0, 0, 0, 0, false, 12079, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  12029,  true),
				});

				// XAxisDefinition, i=12046, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- XYArrayItemType/12038
				AddDefaultAddressSpaceNodeVariable(12046, "XAxisDefinition", "XAxisDefinition", "", 0, 0, 0, 0, 0, false, 12079, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  12038,  true),
				});

				// XAxisDefinition, i=12055, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ImageItemType/12047
				AddDefaultAddressSpaceNodeVariable(12055, "XAxisDefinition", "XAxisDefinition", "", 0, 0, 0, 0, 0, false, 12079, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  12047,  true),
				});

				// YAxisDefinition, i=12056, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ImageItemType/12047
				AddDefaultAddressSpaceNodeVariable(12056, "YAxisDefinition", "YAxisDefinition", "", 0, 0, 0, 0, 0, false, 12079, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  12047,  true),
				});

				// XAxisDefinition, i=12065, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- CubeItemType/12057
				AddDefaultAddressSpaceNodeVariable(12065, "XAxisDefinition", "XAxisDefinition", "", 0, 0, 0, 0, 0, false, 12079, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  12057,  true),
				});

				// YAxisDefinition, i=12066, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- CubeItemType/12057
				AddDefaultAddressSpaceNodeVariable(12066, "YAxisDefinition", "YAxisDefinition", "", 0, 0, 0, 0, 0, false, 12079, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  12057,  true),
				});

				// ZAxisDefinition, i=12067, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- CubeItemType/12057
				AddDefaultAddressSpaceNodeVariable(12067, "ZAxisDefinition", "ZAxisDefinition", "", 0, 0, 0, 0, 0, false, 12079, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  12057,  true),
				});

				// AxisDefinition, i=12076, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NDimensionArrayItemType/12068
				AddDefaultAddressSpaceNodeVariable(12076, "AxisDefinition", "AxisDefinition", "", 0, 0, 0, 0, 0, false, 12079, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  12068,  true),
				});

				// Id, i=8996, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- TwoStateVariableType/8995
				AddDefaultAddressSpaceNodeVariable(8996, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  8995,  true),
				});

				// TransitionTime, i=9000, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- TwoStateVariableType/8995
				AddDefaultAddressSpaceNodeVariable(9000, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  8995,  true),
				});

				// EffectiveTransitionTime, i=9001, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- TwoStateVariableType/8995
				AddDefaultAddressSpaceNodeVariable(9001, "EffectiveTransitionTime", "EffectiveTransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  8995,  true),
				});

				// TrueState, i=11110, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- TwoStateVariableType/8995
				AddDefaultAddressSpaceNodeVariable(11110, "TrueState", "TrueState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  8995,  true),
				});

				// FalseState, i=11111, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- TwoStateVariableType/8995
				AddDefaultAddressSpaceNodeVariable(11111, "FalseState", "FalseState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  8995,  true),
				});

				// SourceTimestamp, i=9003, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ConditionVariableType/9002
				AddDefaultAddressSpaceNodeVariable(9003, "SourceTimestamp", "SourceTimestamp", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9002,  true),
				});

				// ConditionClassId, i=11112, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ConditionType/2782
				AddDefaultAddressSpaceNodeVariable(11112, "ConditionClassId", "ConditionClassId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2782,  true),
				});

				// ConditionClassName, i=11113, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ConditionType/2782
				AddDefaultAddressSpaceNodeVariable(11113, "ConditionClassName", "ConditionClassName", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2782,  true),
				});

				// ConditionName, i=9009, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ConditionType/2782
				AddDefaultAddressSpaceNodeVariable(9009, "ConditionName", "ConditionName", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2782,  true),
				});

				// BranchId, i=9010, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ConditionType/2782
				AddDefaultAddressSpaceNodeVariable(9010, "BranchId", "BranchId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2782,  true),
				});

				// Retain, i=3874, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ConditionType/2782
				AddDefaultAddressSpaceNodeVariable(3874, "Retain", "Retain", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2782,  true),
				});

				// EnabledState, i=9011, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9012
				//	HasProperty/46 -> EffectiveDisplayName/9015
				//	HasProperty/46 -> TransitionTime/9016
				//	HasProperty/46 -> EffectiveTransitionTime/9017
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ConditionType/2782
				AddDefaultAddressSpaceNodeVariable(9011, "EnabledState", "EnabledState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9012,  false),
					(46,  9015,  false),
					(46,  9016,  false),
					(46,  9017,  false),
					(40,  8995,  false),
					(37,  78,  false),
					(47,  2782,  true),
				});

				// Id, i=9012, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- EnabledState/9011
				AddDefaultAddressSpaceNodeVariable(9012, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9011,  true),
				});

				// EffectiveDisplayName, i=9015, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- EnabledState/9011
				AddDefaultAddressSpaceNodeVariable(9015, "EffectiveDisplayName", "EffectiveDisplayName", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  9011,  true),
				});

				// TransitionTime, i=9016, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- EnabledState/9011
				AddDefaultAddressSpaceNodeVariable(9016, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  9011,  true),
				});

				// EffectiveTransitionTime, i=9017, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- EnabledState/9011
				AddDefaultAddressSpaceNodeVariable(9017, "EffectiveTransitionTime", "EffectiveTransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  9011,  true),
				});

				// Quality, i=9020, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> SourceTimestamp/9021
				//	HasTypeDefinition/40 -> ConditionVariableType/9002
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ConditionType/2782
				AddDefaultAddressSpaceNodeVariable(9020, "Quality", "Quality", "", 0, 0, 0, 0, 0, false, 19, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9021,  false),
					(40,  9002,  false),
					(37,  78,  false),
					(47,  2782,  true),
				});

				// SourceTimestamp, i=9021, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Quality/9020
				AddDefaultAddressSpaceNodeVariable(9021, "SourceTimestamp", "SourceTimestamp", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9020,  true),
				});

				// LastSeverity, i=9022, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> SourceTimestamp/9023
				//	HasTypeDefinition/40 -> ConditionVariableType/9002
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ConditionType/2782
				AddDefaultAddressSpaceNodeVariable(9022, "LastSeverity", "LastSeverity", "", 0, 0, 0, 0, 0, false, 5, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9023,  false),
					(40,  9002,  false),
					(37,  78,  false),
					(47,  2782,  true),
				});

				// SourceTimestamp, i=9023, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- LastSeverity/9022
				AddDefaultAddressSpaceNodeVariable(9023, "SourceTimestamp", "SourceTimestamp", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9022,  true),
				});

				// Comment, i=9024, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> SourceTimestamp/9025
				//	HasTypeDefinition/40 -> ConditionVariableType/9002
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ConditionType/2782
				AddDefaultAddressSpaceNodeVariable(9024, "Comment", "Comment", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9025,  false),
					(40,  9002,  false),
					(37,  78,  false),
					(47,  2782,  true),
				});

				// SourceTimestamp, i=9025, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Comment/9024
				AddDefaultAddressSpaceNodeVariable(9025, "SourceTimestamp", "SourceTimestamp", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9024,  true),
				});

				// ClientUserId, i=9026, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ConditionType/2782
				AddDefaultAddressSpaceNodeVariable(9026, "ClientUserId", "ClientUserId", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2782,  true),
				});

				// InputArguments, i=9030, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AddComment/9029
				AddDefaultAddressSpaceNodeVariable(9030, "InputArguments", "InputArguments", "The identifier for the event to comment.", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9029,  true),
				});

				// InputArguments, i=3876, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ConditionRefresh/3875
				AddDefaultAddressSpaceNodeVariable(3876, "InputArguments", "InputArguments", "The identifier for the suscription to refresh.", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3875,  true),
				});

				// EnabledState, i=9035, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9036
				//	i=9004/9004 -> DialogState/9055
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- DialogConditionType/2830
				AddDefaultAddressSpaceNodeVariable(9035, "EnabledState", "EnabledState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9036,  false),
					(9004,  9055,  false),
					(40,  8995,  false),
					(37,  78,  false),
					(47,  2830,  true),
				});

				// Id, i=9036, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- EnabledState/9035
				AddDefaultAddressSpaceNodeVariable(9036, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9035,  true),
				});

				// DialogState, i=9055, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9056
				//	HasProperty/46 -> TransitionTime/9060
				//	i=9004/9004 <- EnabledState/9035
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- DialogConditionType/2830
				AddDefaultAddressSpaceNodeVariable(9055, "DialogState", "DialogState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9056,  false),
					(46,  9060,  false),
					(9004,  9035,  true),
					(40,  8995,  false),
					(37,  78,  false),
					(47,  2830,  true),
				});

				// Id, i=9056, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- DialogState/9055
				AddDefaultAddressSpaceNodeVariable(9056, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9055,  true),
				});

				// TransitionTime, i=9060, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- DialogState/9055
				AddDefaultAddressSpaceNodeVariable(9060, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  9055,  true),
				});

				// Prompt, i=2831, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- DialogConditionType/2830
				AddDefaultAddressSpaceNodeVariable(2831, "Prompt", "Prompt", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2830,  true),
				});

				// ResponseOptionSet, i=9064, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- DialogConditionType/2830
				AddDefaultAddressSpaceNodeVariable(9064, "ResponseOptionSet", "ResponseOptionSet", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2830,  true),
				});

				// DefaultResponse, i=9065, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- DialogConditionType/2830
				AddDefaultAddressSpaceNodeVariable(9065, "DefaultResponse", "DefaultResponse", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2830,  true),
				});

				// OkResponse, i=9066, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- DialogConditionType/2830
				AddDefaultAddressSpaceNodeVariable(9066, "OkResponse", "OkResponse", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2830,  true),
				});

				// CancelResponse, i=9067, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- DialogConditionType/2830
				AddDefaultAddressSpaceNodeVariable(9067, "CancelResponse", "CancelResponse", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2830,  true),
				});

				// LastResponse, i=9068, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- DialogConditionType/2830
				AddDefaultAddressSpaceNodeVariable(9068, "LastResponse", "LastResponse", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2830,  true),
				});

				// InputArguments, i=9070, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Respond/9069
				AddDefaultAddressSpaceNodeVariable(9070, "InputArguments", "InputArguments", "The response to the dialog condition.", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9069,  true),
				});

				// EnabledState, i=9073, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9074
				//	i=9004/9004 -> AckedState/9093
				//	i=9004/9004 -> ConfirmedState/9102
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- AcknowledgeableConditionType/2881
				AddDefaultAddressSpaceNodeVariable(9073, "EnabledState", "EnabledState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9074,  false),
					(9004,  9093,  false),
					(9004,  9102,  false),
					(40,  8995,  false),
					(37,  78,  false),
					(47,  2881,  true),
				});

				// Id, i=9074, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- EnabledState/9073
				AddDefaultAddressSpaceNodeVariable(9074, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9073,  true),
				});

				// AckedState, i=9093, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9094
				//	HasProperty/46 -> TransitionTime/9098
				//	i=9004/9004 <- EnabledState/9073
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- AcknowledgeableConditionType/2881
				AddDefaultAddressSpaceNodeVariable(9093, "AckedState", "AckedState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9094,  false),
					(46,  9098,  false),
					(9004,  9073,  true),
					(40,  8995,  false),
					(37,  78,  false),
					(47,  2881,  true),
				});

				// Id, i=9094, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AckedState/9093
				AddDefaultAddressSpaceNodeVariable(9094, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9093,  true),
				});

				// TransitionTime, i=9098, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- AckedState/9093
				AddDefaultAddressSpaceNodeVariable(9098, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  9093,  true),
				});

				// ConfirmedState, i=9102, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9103
				//	HasProperty/46 -> TransitionTime/9107
				//	i=9004/9004 <- EnabledState/9073
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- AcknowledgeableConditionType/2881
				AddDefaultAddressSpaceNodeVariable(9102, "ConfirmedState", "ConfirmedState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9103,  false),
					(46,  9107,  false),
					(9004,  9073,  true),
					(40,  8995,  false),
					(37,  80,  false),
					(47,  2881,  true),
				});

				// Id, i=9103, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ConfirmedState/9102
				AddDefaultAddressSpaceNodeVariable(9103, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9102,  true),
				});

				// TransitionTime, i=9107, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- ConfirmedState/9102
				AddDefaultAddressSpaceNodeVariable(9107, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  9102,  true),
				});

				// InputArguments, i=9112, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Acknowledge/9111
				AddDefaultAddressSpaceNodeVariable(9112, "InputArguments", "InputArguments", "The identifier for the event to comment.", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9111,  true),
				});

				// InputArguments, i=9114, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Confirm/9113
				AddDefaultAddressSpaceNodeVariable(9114, "InputArguments", "InputArguments", "The identifier for the event to comment.", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9113,  true),
				});

				// EnabledState, i=9118, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9119
				//	i=9004/9004 -> ActiveState/9160
				//	i=9004/9004 -> SuppressedState/9169
				//	i=9004/9004 -> ShelvingState/9178
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- AlarmConditionType/2915
				AddDefaultAddressSpaceNodeVariable(9118, "EnabledState", "EnabledState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9119,  false),
					(9004,  9160,  false),
					(9004,  9169,  false),
					(9004,  9178,  false),
					(40,  8995,  false),
					(37,  78,  false),
					(47,  2915,  true),
				});

				// Id, i=9119, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- EnabledState/9118
				AddDefaultAddressSpaceNodeVariable(9119, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9118,  true),
				});

				// ActiveState, i=9160, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9161
				//	HasProperty/46 -> EffectiveDisplayName/9164
				//	HasProperty/46 -> TransitionTime/9165
				//	HasProperty/46 -> EffectiveTransitionTime/9166
				//	i=9004/9004 <- EnabledState/9118
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- AlarmConditionType/2915
				AddDefaultAddressSpaceNodeVariable(9160, "ActiveState", "ActiveState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9161,  false),
					(46,  9164,  false),
					(46,  9165,  false),
					(46,  9166,  false),
					(9004,  9118,  true),
					(40,  8995,  false),
					(37,  78,  false),
					(47,  2915,  true),
				});

				// Id, i=9161, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ActiveState/9160
				AddDefaultAddressSpaceNodeVariable(9161, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9160,  true),
				});

				// EffectiveDisplayName, i=9164, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- ActiveState/9160
				AddDefaultAddressSpaceNodeVariable(9164, "EffectiveDisplayName", "EffectiveDisplayName", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  9160,  true),
				});

				// TransitionTime, i=9165, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- ActiveState/9160
				AddDefaultAddressSpaceNodeVariable(9165, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  9160,  true),
				});

				// EffectiveTransitionTime, i=9166, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- ActiveState/9160
				AddDefaultAddressSpaceNodeVariable(9166, "EffectiveTransitionTime", "EffectiveTransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  9160,  true),
				});

				// InputNode, i=11120, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AlarmConditionType/2915
				AddDefaultAddressSpaceNodeVariable(11120, "InputNode", "InputNode", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2915,  true),
				});

				// SuppressedState, i=9169, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9170
				//	HasProperty/46 -> TransitionTime/9174
				//	i=9004/9004 <- EnabledState/9118
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- AlarmConditionType/2915
				AddDefaultAddressSpaceNodeVariable(9169, "SuppressedState", "SuppressedState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9170,  false),
					(46,  9174,  false),
					(9004,  9118,  true),
					(40,  8995,  false),
					(37,  80,  false),
					(47,  2915,  true),
				});

			}
			private void Part13()
			{
				// Id, i=9170, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- SuppressedState/9169
				AddDefaultAddressSpaceNodeVariable(9170, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9169,  true),
				});

				// TransitionTime, i=9174, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- SuppressedState/9169
				AddDefaultAddressSpaceNodeVariable(9174, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  9169,  true),
				});

				// CurrentState, i=9179, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9180
				//	HasTypeDefinition/40 -> FiniteStateVariableType/2760
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ShelvingState/9178
				AddDefaultAddressSpaceNodeVariable(9179, "CurrentState", "CurrentState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9180,  false),
					(40,  2760,  false),
					(37,  78,  false),
					(47,  9178,  true),
				});

				// Id, i=9180, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- CurrentState/9179
				AddDefaultAddressSpaceNodeVariable(9180, "Id", "Id", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9179,  true),
				});

				// LastTransition, i=9184, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9185
				//	HasProperty/46 -> TransitionTime/9188
				//	HasTypeDefinition/40 -> FiniteTransitionVariableType/2767
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- ShelvingState/9178
				AddDefaultAddressSpaceNodeVariable(9184, "LastTransition", "LastTransition", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9185,  false),
					(46,  9188,  false),
					(40,  2767,  false),
					(37,  80,  false),
					(47,  9178,  true),
				});

				// Id, i=9185, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- LastTransition/9184
				AddDefaultAddressSpaceNodeVariable(9185, "Id", "Id", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9184,  true),
				});

				// TransitionTime, i=9188, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- LastTransition/9184
				AddDefaultAddressSpaceNodeVariable(9188, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  9184,  true),
				});

				// UnshelveTime, i=9189, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ShelvingState/9178
				AddDefaultAddressSpaceNodeVariable(9189, "UnshelveTime", "UnshelveTime", "", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9178,  true),
				});

				// InputArguments, i=9214, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- TimedShelve/9213
				AddDefaultAddressSpaceNodeVariable(9214, "InputArguments", "InputArguments", "If not 0, this parameter specifies a fixed time for which the Alarm is to be shelved.", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9213,  true),
				});

				// SuppressedOrShelved, i=9215, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AlarmConditionType/2915
				AddDefaultAddressSpaceNodeVariable(9215, "SuppressedOrShelved", "SuppressedOrShelved", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2915,  true),
				});

				// MaxTimeShelved, i=9216, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- AlarmConditionType/2915
				AddDefaultAddressSpaceNodeVariable(9216, "MaxTimeShelved", "MaxTimeShelved", "", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2915,  true),
				});

				// UnshelveTime, i=9115, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ShelvedStateMachineType/2929
				AddDefaultAddressSpaceNodeVariable(9115, "UnshelveTime", "UnshelveTime", "", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2929,  true),
				});

				// StateNumber, i=6098, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Unshelved/2930
				AddDefaultAddressSpaceNodeVariable(6098, "StateNumber", "StateNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2930,  true),
				});

				// StateNumber, i=6100, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- TimedShelved/2932
				AddDefaultAddressSpaceNodeVariable(6100, "StateNumber", "StateNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2932,  true),
				});

				// StateNumber, i=6101, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- OneShotShelved/2933
				AddDefaultAddressSpaceNodeVariable(6101, "StateNumber", "StateNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2933,  true),
				});

				// TransitionNumber, i=11322, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- UnshelvedToTimedShelved/2935
				AddDefaultAddressSpaceNodeVariable(11322, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2935,  true),
				});

				// TransitionNumber, i=11323, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- UnshelvedToOneShotShelved/2936
				AddDefaultAddressSpaceNodeVariable(11323, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2936,  true),
				});

				// TransitionNumber, i=11324, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- TimedShelvedToUnshelved/2940
				AddDefaultAddressSpaceNodeVariable(11324, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2940,  true),
				});

				// TransitionNumber, i=11325, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- TimedShelvedToOneShotShelved/2942
				AddDefaultAddressSpaceNodeVariable(11325, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2942,  true),
				});

				// TransitionNumber, i=11326, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- OneShotShelvedToUnshelved/2943
				AddDefaultAddressSpaceNodeVariable(11326, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2943,  true),
				});

				// TransitionNumber, i=11327, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- OneShotShelvedToTimedShelved/2945
				AddDefaultAddressSpaceNodeVariable(11327, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2945,  true),
				});

				// InputArguments, i=2991, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- TimedShelve/2949
				AddDefaultAddressSpaceNodeVariable(2991, "InputArguments", "InputArguments", "If not 0, this parameter specifies a fixed time for which the Alarm is to be shelved.", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2949,  true),
				});

				// HighHighLimit, i=11124, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- LimitAlarmType/2955
				AddDefaultAddressSpaceNodeVariable(11124, "HighHighLimit", "HighHighLimit", "", 0, 0, 0, 0, 0, false, 11, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2955,  true),
				});

				// HighLimit, i=11125, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- LimitAlarmType/2955
				AddDefaultAddressSpaceNodeVariable(11125, "HighLimit", "HighLimit", "", 0, 0, 0, 0, 0, false, 11, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2955,  true),
				});

				// LowLimit, i=11126, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- LimitAlarmType/2955
				AddDefaultAddressSpaceNodeVariable(11126, "LowLimit", "LowLimit", "", 0, 0, 0, 0, 0, false, 11, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2955,  true),
				});

				// LowLowLimit, i=11127, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- LimitAlarmType/2955
				AddDefaultAddressSpaceNodeVariable(11127, "LowLowLimit", "LowLowLimit", "", 0, 0, 0, 0, 0, false, 11, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2955,  true),
				});

				// StateNumber, i=9330, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HighHigh/9329
				AddDefaultAddressSpaceNodeVariable(9330, "StateNumber", "StateNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9329,  true),
				});

				// StateNumber, i=9332, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- High/9331
				AddDefaultAddressSpaceNodeVariable(9332, "StateNumber", "StateNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9331,  true),
				});

				// StateNumber, i=9334, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Low/9333
				AddDefaultAddressSpaceNodeVariable(9334, "StateNumber", "StateNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9333,  true),
				});

				// StateNumber, i=9336, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- LowLow/9335
				AddDefaultAddressSpaceNodeVariable(9336, "StateNumber", "StateNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9335,  true),
				});

				// TransitionNumber, i=11340, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- LowLowToLow/9337
				AddDefaultAddressSpaceNodeVariable(11340, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9337,  true),
				});

				// TransitionNumber, i=11341, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- LowToLowLow/9338
				AddDefaultAddressSpaceNodeVariable(11341, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9338,  true),
				});

				// TransitionNumber, i=11342, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HighHighToHigh/9339
				AddDefaultAddressSpaceNodeVariable(11342, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9339,  true),
				});

				// TransitionNumber, i=11343, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HighToHighHigh/9340
				AddDefaultAddressSpaceNodeVariable(11343, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9340,  true),
				});

				// ActiveState, i=9398, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9399
				//	i=9004/9004 -> LimitState/9455
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ExclusiveLimitAlarmType/9341
				AddDefaultAddressSpaceNodeVariable(9398, "ActiveState", "ActiveState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9399,  false),
					(9004,  9455,  false),
					(40,  8995,  false),
					(37,  78,  false),
					(47,  9341,  true),
				});

				// Id, i=9399, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ActiveState/9398
				AddDefaultAddressSpaceNodeVariable(9399, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9398,  true),
				});

				// CurrentState, i=9456, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9457
				//	HasTypeDefinition/40 -> FiniteStateVariableType/2760
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- LimitState/9455
				AddDefaultAddressSpaceNodeVariable(9456, "CurrentState", "CurrentState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9457,  false),
					(40,  2760,  false),
					(37,  78,  false),
					(47,  9455,  true),
				});

				// Id, i=9457, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- CurrentState/9456
				AddDefaultAddressSpaceNodeVariable(9457, "Id", "Id", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9456,  true),
				});

				// LastTransition, i=9461, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9462
				//	HasProperty/46 -> TransitionTime/9465
				//	HasTypeDefinition/40 -> FiniteTransitionVariableType/2767
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- LimitState/9455
				AddDefaultAddressSpaceNodeVariable(9461, "LastTransition", "LastTransition", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9462,  false),
					(46,  9465,  false),
					(40,  2767,  false),
					(37,  80,  false),
					(47,  9455,  true),
				});

				// Id, i=9462, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- LastTransition/9461
				AddDefaultAddressSpaceNodeVariable(9462, "Id", "Id", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9461,  true),
				});

				// TransitionTime, i=9465, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- LastTransition/9461
				AddDefaultAddressSpaceNodeVariable(9465, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  9461,  true),
				});

				// ActiveState, i=9963, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/9964
				//	i=9004/9004 -> HighHighState/10020
				//	i=9004/9004 -> HighState/10029
				//	i=9004/9004 -> LowState/10038
				//	i=9004/9004 -> LowLowState/10047
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- NonExclusiveLimitAlarmType/9906
				AddDefaultAddressSpaceNodeVariable(9963, "ActiveState", "ActiveState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9964,  false),
					(9004,  10020,  false),
					(9004,  10029,  false),
					(9004,  10038,  false),
					(9004,  10047,  false),
					(40,  8995,  false),
					(37,  78,  false),
					(47,  9906,  true),
				});

				// Id, i=9964, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ActiveState/9963
				AddDefaultAddressSpaceNodeVariable(9964, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9963,  true),
				});

				// HighHighState, i=10020, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/10021
				//	HasProperty/46 -> TransitionTime/10025
				//	i=9004/9004 <- ActiveState/9963
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- NonExclusiveLimitAlarmType/9906
				AddDefaultAddressSpaceNodeVariable(10020, "HighHighState", "HighHighState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  10021,  false),
					(46,  10025,  false),
					(9004,  9963,  true),
					(40,  8995,  false),
					(37,  80,  false),
					(47,  9906,  true),
				});

				// Id, i=10021, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HighHighState/10020
				AddDefaultAddressSpaceNodeVariable(10021, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  10020,  true),
				});

				// TransitionTime, i=10025, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- HighHighState/10020
				AddDefaultAddressSpaceNodeVariable(10025, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  10020,  true),
				});

				// HighState, i=10029, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/10030
				//	HasProperty/46 -> TransitionTime/10034
				//	i=9004/9004 <- ActiveState/9963
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- NonExclusiveLimitAlarmType/9906
				AddDefaultAddressSpaceNodeVariable(10029, "HighState", "HighState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  10030,  false),
					(46,  10034,  false),
					(9004,  9963,  true),
					(40,  8995,  false),
					(37,  80,  false),
					(47,  9906,  true),
				});

				// Id, i=10030, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HighState/10029
				AddDefaultAddressSpaceNodeVariable(10030, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  10029,  true),
				});

				// TransitionTime, i=10034, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- HighState/10029
				AddDefaultAddressSpaceNodeVariable(10034, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  10029,  true),
				});

				// LowState, i=10038, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/10039
				//	HasProperty/46 -> TransitionTime/10043
				//	i=9004/9004 <- ActiveState/9963
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- NonExclusiveLimitAlarmType/9906
				AddDefaultAddressSpaceNodeVariable(10038, "LowState", "LowState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  10039,  false),
					(46,  10043,  false),
					(9004,  9963,  true),
					(40,  8995,  false),
					(37,  80,  false),
					(47,  9906,  true),
				});

				// Id, i=10039, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- LowState/10038
				AddDefaultAddressSpaceNodeVariable(10039, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  10038,  true),
				});

				// TransitionTime, i=10043, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- LowState/10038
				AddDefaultAddressSpaceNodeVariable(10043, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  10038,  true),
				});

				// LowLowState, i=10047, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/10048
				//	HasProperty/46 -> TransitionTime/10052
				//	i=9004/9004 <- ActiveState/9963
				//	HasTypeDefinition/40 -> TwoStateVariableType/8995
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- NonExclusiveLimitAlarmType/9906
				AddDefaultAddressSpaceNodeVariable(10047, "LowLowState", "LowLowState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  10048,  false),
					(46,  10052,  false),
					(9004,  9963,  true),
					(40,  8995,  false),
					(37,  80,  false),
					(47,  9906,  true),
				});

				// Id, i=10048, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- LowLowState/10047
				AddDefaultAddressSpaceNodeVariable(10048, "Id", "Id", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  10047,  true),
				});

				// TransitionTime, i=10052, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- LowLowState/10047
				AddDefaultAddressSpaceNodeVariable(10052, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  10047,  true),
				});

				// SetpointNode, i=10522, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NonExclusiveDeviationAlarmType/10368
				AddDefaultAddressSpaceNodeVariable(10522, "SetpointNode", "SetpointNode", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  10368,  true),
				});

				// SetpointNode, i=9905, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ExclusiveDeviationAlarmType/9764
				AddDefaultAddressSpaceNodeVariable(9905, "SetpointNode", "SetpointNode", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  9764,  true),
				});

				// NormalState, i=11158, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- OffNormalAlarmType/10637
				AddDefaultAddressSpaceNodeVariable(11158, "NormalState", "NormalState", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  10637,  true),
				});

				// EventId, i=4170, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditConditionCommentEventType/2829
				AddDefaultAddressSpaceNodeVariable(4170, "EventId", "EventId", "A globally unique identifier for the event.", 0, 0, 0, 0, 0, false, 15, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2829,  true),
				});

				// Comment, i=11851, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditConditionCommentEventType/2829
				AddDefaultAddressSpaceNodeVariable(11851, "Comment", "Comment", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2829,  true),
				});

				// SelectedResponse, i=11852, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditConditionRespondEventType/8927
				AddDefaultAddressSpaceNodeVariable(11852, "SelectedResponse", "SelectedResponse", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  8927,  true),
				});

				// EventId, i=8945, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditConditionAcknowledgeEventType/8944
				AddDefaultAddressSpaceNodeVariable(8945, "EventId", "EventId", "A globally unique identifier for the event.", 0, 0, 0, 0, 0, false, 15, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  8944,  true),
				});

				// Comment, i=11853, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditConditionAcknowledgeEventType/8944
				AddDefaultAddressSpaceNodeVariable(11853, "Comment", "Comment", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  8944,  true),
				});

				// EventId, i=8962, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditConditionConfirmEventType/8961
				AddDefaultAddressSpaceNodeVariable(8962, "EventId", "EventId", "A globally unique identifier for the event.", 0, 0, 0, 0, 0, false, 15, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  8961,  true),
				});

				// Comment, i=11854, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditConditionConfirmEventType/8961
				AddDefaultAddressSpaceNodeVariable(11854, "Comment", "Comment", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  8961,  true),
				});

				// ShelvingTime, i=11855, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditConditionShelvingEventType/11093
				AddDefaultAddressSpaceNodeVariable(11855, "ShelvingTime", "ShelvingTime", "", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11093,  true),
				});

				// CurrentState, i=3830, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/3831
				//	HasProperty/46 -> Number/3833
				//	HasTypeDefinition/40 -> FiniteStateVariableType/2760
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeVariable(3830, "CurrentState", "CurrentState", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3831,  false),
					(46,  3833,  false),
					(40,  2760,  false),
					(37,  78,  false),
					(47,  2391,  true),
				});

				// Id, i=3831, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- CurrentState/3830
				AddDefaultAddressSpaceNodeVariable(3831, "Id", "Id", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3830,  true),
				});

				// Number, i=3833, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- CurrentState/3830
				AddDefaultAddressSpaceNodeVariable(3833, "Number", "Number", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3830,  true),
				});

				// LastTransition, i=3835, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/3836
				//	HasProperty/46 -> Number/3838
				//	HasProperty/46 -> TransitionTime/3839
				//	HasTypeDefinition/40 -> FiniteTransitionVariableType/2767
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeVariable(3835, "LastTransition", "LastTransition", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3836,  false),
					(46,  3838,  false),
					(46,  3839,  false),
					(40,  2767,  false),
					(37,  78,  false),
					(47,  2391,  true),
				});

				// Id, i=3836, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- LastTransition/3835
				AddDefaultAddressSpaceNodeVariable(3836, "Id", "Id", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3835,  true),
				});

				// Number, i=3838, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- LastTransition/3835
				AddDefaultAddressSpaceNodeVariable(3838, "Number", "Number", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3835,  true),
				});

				// TransitionTime, i=3839, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- LastTransition/3835
				AddDefaultAddressSpaceNodeVariable(3839, "TransitionTime", "TransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3835,  true),
				});

				// Creatable, i=2392, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeVariable(2392, "Creatable", "Creatable", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2391,  true),
				});

				// Deletable, i=2393, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeVariable(2393, "Deletable", "Deletable", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2391,  true),
				});

				// AutoDelete, i=2394, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> MandatoryShared/79
				//	HasProperty/46 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeVariable(2394, "AutoDelete", "AutoDelete", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  79,  false),
					(46,  2391,  true),
				});

				// RecycleCount, i=2395, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeVariable(2395, "RecycleCount", "RecycleCount", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2391,  true),
				});

				// InstanceCount, i=2396, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeVariable(2396, "InstanceCount", "InstanceCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2391,  true),
				});

				// MaxInstanceCount, i=2397, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeVariable(2397, "MaxInstanceCount", "MaxInstanceCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2391,  true),
				});

				// MaxRecycleCount, i=2398, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeVariable(2398, "MaxRecycleCount", "MaxRecycleCount", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  2391,  true),
				});

				// ProgramDiagnostics, i=2399, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> CreateSessionId/3840
				//	HasProperty/46 -> CreateClientName/3841
				//	HasProperty/46 -> InvocationCreationTime/3842
				//	HasProperty/46 -> LastTransitionTime/3843
				//	HasProperty/46 -> LastMethodCall/3844
				//	HasProperty/46 -> LastMethodSessionId/3845
				//	HasProperty/46 -> LastMethodInputArguments/3846
				//	HasProperty/46 -> LastMethodOutputArguments/3847
				//	HasProperty/46 -> LastMethodCallTime/3848
				//	HasProperty/46 -> LastMethodReturnStatus/3849
				//	HasTypeDefinition/40 -> ProgramDiagnosticType/2380
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeVariable(2399, "ProgramDiagnostics", "ProgramDiagnostics", "", 0, 0, 0, 0, 0, false, 894, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3840,  false),
					(46,  3841,  false),
					(46,  3842,  false),
					(46,  3843,  false),
					(46,  3844,  false),
					(46,  3845,  false),
					(46,  3846,  false),
					(46,  3847,  false),
					(46,  3848,  false),
					(46,  3849,  false),
					(40,  2380,  false),
					(37,  80,  false),
					(47,  2391,  true),
				});

				// CreateSessionId, i=3840, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnostics/2399
				AddDefaultAddressSpaceNodeVariable(3840, "CreateSessionId", "CreateSessionId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2399,  true),
				});

				// CreateClientName, i=3841, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnostics/2399
				AddDefaultAddressSpaceNodeVariable(3841, "CreateClientName", "CreateClientName", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2399,  true),
				});

				// InvocationCreationTime, i=3842, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnostics/2399
				AddDefaultAddressSpaceNodeVariable(3842, "InvocationCreationTime", "InvocationCreationTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2399,  true),
				});

				// LastTransitionTime, i=3843, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnostics/2399
				AddDefaultAddressSpaceNodeVariable(3843, "LastTransitionTime", "LastTransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2399,  true),
				});

				// LastMethodCall, i=3844, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnostics/2399
				AddDefaultAddressSpaceNodeVariable(3844, "LastMethodCall", "LastMethodCall", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2399,  true),
				});

				// LastMethodSessionId, i=3845, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnostics/2399
				AddDefaultAddressSpaceNodeVariable(3845, "LastMethodSessionId", "LastMethodSessionId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2399,  true),
				});

				// LastMethodInputArguments, i=3846, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnostics/2399
				AddDefaultAddressSpaceNodeVariable(3846, "LastMethodInputArguments", "LastMethodInputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2399,  true),
				});

				// LastMethodOutputArguments, i=3847, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnostics/2399
				AddDefaultAddressSpaceNodeVariable(3847, "LastMethodOutputArguments", "LastMethodOutputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2399,  true),
				});

				// LastMethodCallTime, i=3848, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnostics/2399
				AddDefaultAddressSpaceNodeVariable(3848, "LastMethodCallTime", "LastMethodCallTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2399,  true),
				});

				// LastMethodReturnStatus, i=3849, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnostics/2399
				AddDefaultAddressSpaceNodeVariable(3849, "LastMethodReturnStatus", "LastMethodReturnStatus", "", 0, 0, 0, 0, 0, false, 299, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2399,  true),
				});

				// StateNumber, i=2401, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Ready/2400
				AddDefaultAddressSpaceNodeVariable(2401, "StateNumber", "StateNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2400,  true),
				});

				// StateNumber, i=2403, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Running/2402
				AddDefaultAddressSpaceNodeVariable(2403, "StateNumber", "StateNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2402,  true),
				});

			}
			private void Part14()
			{
				// StateNumber, i=2405, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Suspended/2404
				AddDefaultAddressSpaceNodeVariable(2405, "StateNumber", "StateNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2404,  true),
				});

				// StateNumber, i=2407, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Halted/2406
				AddDefaultAddressSpaceNodeVariable(2407, "StateNumber", "StateNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2406,  true),
				});

				// TransitionNumber, i=2409, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HaltedToReady/2408
				AddDefaultAddressSpaceNodeVariable(2409, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2408,  true),
				});

				// TransitionNumber, i=2411, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ReadyToRunning/2410
				AddDefaultAddressSpaceNodeVariable(2411, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2410,  true),
				});

				// TransitionNumber, i=2413, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- RunningToHalted/2412
				AddDefaultAddressSpaceNodeVariable(2413, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2412,  true),
				});

				// TransitionNumber, i=2415, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- RunningToReady/2414
				AddDefaultAddressSpaceNodeVariable(2415, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2414,  true),
				});

				// TransitionNumber, i=2417, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- RunningToSuspended/2416
				AddDefaultAddressSpaceNodeVariable(2417, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2416,  true),
				});

				// TransitionNumber, i=2419, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- SuspendedToRunning/2418
				AddDefaultAddressSpaceNodeVariable(2419, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2418,  true),
				});

				// TransitionNumber, i=2421, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- SuspendedToHalted/2420
				AddDefaultAddressSpaceNodeVariable(2421, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2420,  true),
				});

				// TransitionNumber, i=2423, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- SuspendedToReady/2422
				AddDefaultAddressSpaceNodeVariable(2423, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2422,  true),
				});

				// TransitionNumber, i=2425, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ReadyToHalted/2424
				AddDefaultAddressSpaceNodeVariable(2425, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2424,  true),
				});

				// IntermediateResult, i=2379, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramTransitionEventType/2378
				AddDefaultAddressSpaceNodeVariable(2379, "IntermediateResult", "IntermediateResult", "", 0, 0, 0, 0, 0, false, 6, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2378,  true),
				});

				// TransitionNumber, i=11875, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditProgramTransitionEventType/11856
				AddDefaultAddressSpaceNodeVariable(11875, "TransitionNumber", "TransitionNumber", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11856,  true),
				});

				// Transition, i=3825, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> Id/3826
				//	HasTypeDefinition/40 -> FiniteTransitionVariableType/2767
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ProgramTransitionAuditEventType/3806
				AddDefaultAddressSpaceNodeVariable(3825, "Transition", "Transition", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3826,  false),
					(40,  2767,  false),
					(37,  78,  false),
					(47,  3806,  true),
				});

				// Id, i=3826, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- Transition/3825
				AddDefaultAddressSpaceNodeVariable(3826, "Id", "Id", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3825,  true),
				});

				// CreateSessionId, i=2381, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnosticType/2380
				AddDefaultAddressSpaceNodeVariable(2381, "CreateSessionId", "CreateSessionId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2380,  true),
				});

				// CreateClientName, i=2382, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnosticType/2380
				AddDefaultAddressSpaceNodeVariable(2382, "CreateClientName", "CreateClientName", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2380,  true),
				});

				// InvocationCreationTime, i=2383, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnosticType/2380
				AddDefaultAddressSpaceNodeVariable(2383, "InvocationCreationTime", "InvocationCreationTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2380,  true),
				});

				// LastTransitionTime, i=2384, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnosticType/2380
				AddDefaultAddressSpaceNodeVariable(2384, "LastTransitionTime", "LastTransitionTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2380,  true),
				});

				// LastMethodCall, i=2385, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnosticType/2380
				AddDefaultAddressSpaceNodeVariable(2385, "LastMethodCall", "LastMethodCall", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2380,  true),
				});

				// LastMethodSessionId, i=2386, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnosticType/2380
				AddDefaultAddressSpaceNodeVariable(2386, "LastMethodSessionId", "LastMethodSessionId", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2380,  true),
				});

				// LastMethodInputArguments, i=2387, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnosticType/2380
				AddDefaultAddressSpaceNodeVariable(2387, "LastMethodInputArguments", "LastMethodInputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2380,  true),
				});

				// LastMethodOutputArguments, i=2388, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnosticType/2380
				AddDefaultAddressSpaceNodeVariable(2388, "LastMethodOutputArguments", "LastMethodOutputArguments", "", 0, 0, 0, 0, 0, false, 296, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2380,  true),
				});

				// LastMethodCallTime, i=2389, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnosticType/2380
				AddDefaultAddressSpaceNodeVariable(2389, "LastMethodCallTime", "LastMethodCallTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2380,  true),
				});

				// LastMethodReturnStatus, i=2390, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ProgramDiagnosticType/2380
				AddDefaultAddressSpaceNodeVariable(2390, "LastMethodReturnStatus", "LastMethodReturnStatus", "", 0, 0, 0, 0, 0, false, 299, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2380,  true),
				});

				// Annotations, i=11214, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(11214, "Annotations", "Annotations", "", 0, 0, 0, 0, 0, false, 891, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// TreatUncertainAsBad, i=11168, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AggregateConfiguration/3059
				AddDefaultAddressSpaceNodeVariable(11168, "TreatUncertainAsBad", "TreatUncertainAsBad", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3059,  true),
				});

				// PercentDataBad, i=11169, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AggregateConfiguration/3059
				AddDefaultAddressSpaceNodeVariable(11169, "PercentDataBad", "PercentDataBad", "", 0, 0, 0, 0, 0, false, 3, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3059,  true),
				});

				// PercentDataGood, i=11170, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AggregateConfiguration/3059
				AddDefaultAddressSpaceNodeVariable(11170, "PercentDataGood", "PercentDataGood", "", 0, 0, 0, 0, 0, false, 3, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3059,  true),
				});

				// UseSlopedExtrapolation, i=11171, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AggregateConfiguration/3059
				AddDefaultAddressSpaceNodeVariable(11171, "UseSlopedExtrapolation", "UseSlopedExtrapolation", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3059,  true),
				});

				// Stepped, i=2323, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoricalDataConfigurationType/2318
				AddDefaultAddressSpaceNodeVariable(2323, "Stepped", "Stepped", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2318,  true),
				});

				// Definition, i=2324, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- HistoricalDataConfigurationType/2318
				AddDefaultAddressSpaceNodeVariable(2324, "Definition", "Definition", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2318,  true),
				});

				// MaxTimeInterval, i=2325, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- HistoricalDataConfigurationType/2318
				AddDefaultAddressSpaceNodeVariable(2325, "MaxTimeInterval", "MaxTimeInterval", "", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2318,  true),
				});

				// MinTimeInterval, i=2326, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- HistoricalDataConfigurationType/2318
				AddDefaultAddressSpaceNodeVariable(2326, "MinTimeInterval", "MinTimeInterval", "", 0, 0, 0, 0, 0, false, 290, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2318,  true),
				});

				// ExceptionDeviation, i=2327, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- HistoricalDataConfigurationType/2318
				AddDefaultAddressSpaceNodeVariable(2327, "ExceptionDeviation", "ExceptionDeviation", "", 0, 0, 0, 0, 0, false, 11, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2318,  true),
				});

				// ExceptionDeviationFormat, i=2328, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- HistoricalDataConfigurationType/2318
				AddDefaultAddressSpaceNodeVariable(2328, "ExceptionDeviationFormat", "ExceptionDeviationFormat", "", 0, 0, 0, 0, 0, false, 890, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2318,  true),
				});

				// StartOfArchive, i=11499, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- HistoricalDataConfigurationType/2318
				AddDefaultAddressSpaceNodeVariable(11499, "StartOfArchive", "StartOfArchive", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2318,  true),
				});

				// StartOfOnlineArchive, i=11500, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Optional/80
				//	HasProperty/46 <- HistoricalDataConfigurationType/2318
				AddDefaultAddressSpaceNodeVariable(11500, "StartOfOnlineArchive", "StartOfOnlineArchive", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  80,  false),
					(46,  2318,  true),
				});

				// TreatUncertainAsBad, i=11204, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- AggregateConfiguration/11203
				AddDefaultAddressSpaceNodeVariable(11204, "TreatUncertainAsBad", "TreatUncertainAsBad", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11203,  true),
				});

				// PercentDataBad, i=11205, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- AggregateConfiguration/11203
				AddDefaultAddressSpaceNodeVariable(11205, "PercentDataBad", "PercentDataBad", "", 0, 0, 0, 0, 0, false, 3, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11203,  true),
				});

				// PercentDataGood, i=11206, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- AggregateConfiguration/11203
				AddDefaultAddressSpaceNodeVariable(11206, "PercentDataGood", "PercentDataGood", "", 0, 0, 0, 0, 0, false, 3, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11203,  true),
				});

				// UseSlopedExtrapolation, i=11207, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- AggregateConfiguration/11203
				AddDefaultAddressSpaceNodeVariable(11207, "UseSlopedExtrapolation", "UseSlopedExtrapolation", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11203,  true),
				});

				// Stepped, i=11208, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- HA Configuration/11202
				AddDefaultAddressSpaceNodeVariable(11208, "Stepped", "Stepped", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  11202,  true),
				});

				// HistoricalEventFilter, i=11215, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariable(11215, "HistoricalEventFilter", "HistoricalEventFilter", "", 0, 0, 0, 0, 0, false, 725, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
				});

				// AccessHistoryDataCapability, i=2331, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeVariable(2331, "AccessHistoryDataCapability", "AccessHistoryDataCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2330,  true),
				});

				// AccessHistoryEventsCapability, i=2332, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeVariable(2332, "AccessHistoryEventsCapability", "AccessHistoryEventsCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2330,  true),
				});

				// MaxReturnDataValues, i=11268, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeVariable(11268, "MaxReturnDataValues", "MaxReturnDataValues", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2330,  true),
				});

				// MaxReturnEventValues, i=11269, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeVariable(11269, "MaxReturnEventValues", "MaxReturnEventValues", "", 0, 0, 0, 0, 0, false, 7, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2330,  true),
				});

				// InsertDataCapability, i=2334, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeVariable(2334, "InsertDataCapability", "InsertDataCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2330,  true),
				});

				// ReplaceDataCapability, i=2335, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeVariable(2335, "ReplaceDataCapability", "ReplaceDataCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2330,  true),
				});

				// UpdateDataCapability, i=2336, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeVariable(2336, "UpdateDataCapability", "UpdateDataCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2330,  true),
				});

				// DeleteRawCapability, i=2337, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeVariable(2337, "DeleteRawCapability", "DeleteRawCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2330,  true),
				});

				// DeleteAtTimeCapability, i=2338, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeVariable(2338, "DeleteAtTimeCapability", "DeleteAtTimeCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2330,  true),
				});

				// InsertEventCapability, i=11278, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeVariable(11278, "InsertEventCapability", "InsertEventCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2330,  true),
				});

				// ReplaceEventCapability, i=11279, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeVariable(11279, "ReplaceEventCapability", "ReplaceEventCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2330,  true),
				});

				// UpdateEventCapability, i=11280, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeVariable(11280, "UpdateEventCapability", "UpdateEventCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2330,  true),
				});

				// DeleteEventCapability, i=11501, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeVariable(11501, "DeleteEventCapability", "DeleteEventCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2330,  true),
				});

				// InsertAnnotationCapability, i=11270, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryServerCapabilitiesType/2330
				AddDefaultAddressSpaceNodeVariable(11270, "InsertAnnotationCapability", "InsertAnnotationCapability", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2330,  true),
				});

				// UpdatedNode, i=3025, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryEventUpdateEventType/2999
				AddDefaultAddressSpaceNodeVariable(3025, "UpdatedNode", "UpdatedNode", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2999,  true),
				});

				// PerformInsertReplace, i=3028, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryEventUpdateEventType/2999
				AddDefaultAddressSpaceNodeVariable(3028, "PerformInsertReplace", "PerformInsertReplace", "", 0, 0, 0, 0, 0, false, 11293, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2999,  true),
				});

				// Filter, i=3003, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryEventUpdateEventType/2999
				AddDefaultAddressSpaceNodeVariable(3003, "Filter", "Filter", "", 0, 0, 0, 0, 0, false, 725, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2999,  true),
				});

				// NewValues, i=3029, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryEventUpdateEventType/2999
				AddDefaultAddressSpaceNodeVariable(3029, "NewValues", "NewValues", "", 0, 0, 0, 0, 0, false, 920, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2999,  true),
				});

				// OldValues, i=3030, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryEventUpdateEventType/2999
				AddDefaultAddressSpaceNodeVariable(3030, "OldValues", "OldValues", "", 0, 0, 0, 0, 0, false, 920, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  2999,  true),
				});

				// UpdatedNode, i=3026, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryValueUpdateEventType/3006
				AddDefaultAddressSpaceNodeVariable(3026, "UpdatedNode", "UpdatedNode", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3006,  true),
				});

				// PerformInsertReplace, i=3031, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryValueUpdateEventType/3006
				AddDefaultAddressSpaceNodeVariable(3031, "PerformInsertReplace", "PerformInsertReplace", "", 0, 0, 0, 0, 0, false, 11293, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3006,  true),
				});

				// NewValues, i=3032, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryValueUpdateEventType/3006
				AddDefaultAddressSpaceNodeVariable(3032, "NewValues", "NewValues", "", 0, 0, 0, 0, 0, false, 23, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3006,  true),
				});

				// OldValues, i=3033, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryValueUpdateEventType/3006
				AddDefaultAddressSpaceNodeVariable(3033, "OldValues", "OldValues", "", 0, 0, 0, 0, 0, false, 23, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3006,  true),
				});

				// UpdatedNode, i=3027, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryDeleteEventType/3012
				AddDefaultAddressSpaceNodeVariable(3027, "UpdatedNode", "UpdatedNode", "", 0, 0, 0, 0, 0, false, 17, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3012,  true),
				});

				// IsDeleteModified, i=3015, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryRawModifyDeleteEventType/3014
				AddDefaultAddressSpaceNodeVariable(3015, "IsDeleteModified", "IsDeleteModified", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3014,  true),
				});

				// StartTime, i=3016, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryRawModifyDeleteEventType/3014
				AddDefaultAddressSpaceNodeVariable(3016, "StartTime", "StartTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3014,  true),
				});

				// EndTime, i=3017, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryRawModifyDeleteEventType/3014
				AddDefaultAddressSpaceNodeVariable(3017, "EndTime", "EndTime", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3014,  true),
				});

				// OldValues, i=3034, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryRawModifyDeleteEventType/3014
				AddDefaultAddressSpaceNodeVariable(3034, "OldValues", "OldValues", "", 0, 0, 0, 0, 0, false, 23, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3014,  true),
				});

				// ReqTimes, i=3020, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryAtTimeDeleteEventType/3019
				AddDefaultAddressSpaceNodeVariable(3020, "ReqTimes", "ReqTimes", "", 0, 0, 0, 0, 0, false, 294, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3019,  true),
				});

				// OldValues, i=3021, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryAtTimeDeleteEventType/3019
				AddDefaultAddressSpaceNodeVariable(3021, "OldValues", "OldValues", "", 0, 0, 0, 0, 0, false, 23, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3019,  true),
				});

				// EventIds, i=3023, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryEventDeleteEventType/3022
				AddDefaultAddressSpaceNodeVariable(3023, "EventIds", "EventIds", "", 0, 0, 0, 0, 0, false, 15, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3022,  true),
				});

				// OldValues, i=3024, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AuditHistoryEventDeleteEventType/3022
				AddDefaultAddressSpaceNodeVariable(3024, "OldValues", "OldValues", "", 0, 0, 0, 0, 0, false, 920, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  3022,  true),
				});

				// TreatUncertainAsBad, i=11188, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AggregateConfigurationType/11187
				AddDefaultAddressSpaceNodeVariable(11188, "TreatUncertainAsBad", "TreatUncertainAsBad", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11187,  true),
				});

				// PercentDataBad, i=11189, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AggregateConfigurationType/11187
				AddDefaultAddressSpaceNodeVariable(11189, "PercentDataBad", "PercentDataBad", "", 0, 0, 0, 0, 0, false, 3, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11187,  true),
				});

				// PercentDataGood, i=11190, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AggregateConfigurationType/11187
				AddDefaultAddressSpaceNodeVariable(11190, "PercentDataGood", "PercentDataGood", "", 0, 0, 0, 0, 0, false, 3, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11187,  true),
				});

				// UseSlopedExtrapolation, i=11191, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AggregateConfigurationType/11187
				AddDefaultAddressSpaceNodeVariable(11191, "UseSlopedExtrapolation", "UseSlopedExtrapolation", "", 0, 0, 0, 0, 0, false, 1, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11187,  true),
				});

				// EnumStrings, i=7591, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- IdType/256
				AddDefaultAddressSpaceNodeVariable(7591, "EnumStrings", "EnumStrings", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  256,  true),
				});

				// EnumValues, i=11878, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NodeClass/257
				AddDefaultAddressSpaceNodeVariable(11878, "EnumValues", "EnumValues", "No classes are selected.", 0, 0, 0, 0, 0, false, 7594, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  257,  true),
				});

				// EnumStrings, i=7597, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ApplicationType/307
				AddDefaultAddressSpaceNodeVariable(7597, "EnumStrings", "EnumStrings", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  307,  true),
				});

				// EnumStrings, i=7595, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- MessageSecurityMode/302
				AddDefaultAddressSpaceNodeVariable(7595, "EnumStrings", "EnumStrings", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  302,  true),
				});

				// EnumStrings, i=7596, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- UserTokenType/303
				AddDefaultAddressSpaceNodeVariable(7596, "EnumStrings", "EnumStrings", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  303,  true),
				});

				// EnumStrings, i=7598, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- SecurityTokenRequestType/315
				AddDefaultAddressSpaceNodeVariable(7598, "EnumStrings", "EnumStrings", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  315,  true),
				});

				// EnumValues, i=11881, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- NodeAttributesMask/348
				AddDefaultAddressSpaceNodeVariable(11881, "EnumValues", "EnumValues", "No attribuites provided.", 0, 0, 0, 0, 0, false, 7594, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  348,  true),
				});

				// EnumValues, i=11882, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AttributeWriteMask/347
				AddDefaultAddressSpaceNodeVariable(11882, "EnumValues", "EnumValues", "No attributes are writeable.", 0, 0, 0, 0, 0, false, 7594, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  347,  true),
				});

				// EnumStrings, i=7599, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ComplianceLevel/334
				AddDefaultAddressSpaceNodeVariable(7599, "EnumStrings", "EnumStrings", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  334,  true),
				});

				// EnumStrings, i=7605, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- FilterOperator/576
				AddDefaultAddressSpaceNodeVariable(7605, "EnumStrings", "EnumStrings", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  576,  true),
				});

				// EnumValues, i=11884, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- HistoryUpdateType/11234
				AddDefaultAddressSpaceNodeVariable(11884, "EnumValues", "EnumValues", "", 0, 0, 0, 0, 0, false, 7594, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11234,  true),
				});

				// EnumValues, i=11885, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- PerformUpdateType/11293
				AddDefaultAddressSpaceNodeVariable(11885, "EnumValues", "EnumValues", "", 0, 0, 0, 0, 0, false, 7594, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  11293,  true),
				});

				// EnumValues, i=11886, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- EnumeratedTestType/398
				AddDefaultAddressSpaceNodeVariable(11886, "EnumValues", "EnumValues", "Operation has halted.", 0, 0, 0, 0, 0, false, 7594, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  398,  true),
				});

				// EnumStrings, i=7611, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- RedundancySupport/851
				AddDefaultAddressSpaceNodeVariable(7611, "EnumStrings", "EnumStrings", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  851,  true),
				});

				// EnumStrings, i=7612, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ServerState/852
				AddDefaultAddressSpaceNodeVariable(7612, "EnumStrings", "EnumStrings", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  852,  true),
				});

				// EnumStrings, i=12078, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- AxisScaleEnumeration/12077
				AddDefaultAddressSpaceNodeVariable(12078, "EnumStrings", "EnumStrings", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  12077,  true),
				});

				// EnumStrings, i=7614, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasModellingRule/37 -> Mandatory/78
				//	HasProperty/46 <- ExceptionDeviationFormat/890
				AddDefaultAddressSpaceNodeVariable(7614, "EnumStrings", "EnumStrings", "", 0, 0, 0, 0, 0, false, 21, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(37,  78,  false),
					(46,  890,  true),
				});

				// Opc.Ua, i=8252, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> NamespaceUri/8254
				//	HasComponent/47 -> Argument/8285
				//	HasComponent/47 -> EnumValueType/8291
				//	HasComponent/47 -> TimeZoneDataType/8918
				//	HasComponent/47 -> ApplicationDescription/8300
				//	HasComponent/47 -> UserTokenPolicy/8297
				//	HasComponent/47 -> EndpointDescription/8303
				//	HasComponent/47 -> RegisteredServer/8417
				//	HasComponent/47 -> SignedSoftwareCertificate/8333
				//	HasComponent/47 -> UserIdentityToken/8306
				//	HasComponent/47 -> AnonymousIdentityToken/8309
				//	HasComponent/47 -> UserNameIdentityToken/8312
				//	HasComponent/47 -> X509IdentityToken/8315
				//	HasComponent/47 -> IssuedIdentityToken/8318
				//	HasComponent/47 -> AddNodesItem/8363
				//	HasComponent/47 -> AddReferencesItem/8366
				//	HasComponent/47 -> DeleteNodesItem/8369
				//	HasComponent/47 -> DeleteReferencesItem/8372
				//	HasComponent/47 -> EndpointConfiguration/8321
				//	HasComponent/47 -> SupportedProfile/8324
				//	HasComponent/47 -> SoftwareCertificate/8330
				//	HasComponent/47 -> ContentFilterElement/8564
				//	HasComponent/47 -> ContentFilter/8567
				//	HasComponent/47 -> FilterOperand/8570
				//	HasComponent/47 -> ElementOperand/8573
				//	HasComponent/47 -> LiteralOperand/8576
				//	HasComponent/47 -> AttributeOperand/8579
				//	HasComponent/47 -> SimpleAttributeOperand/8582
				//	HasComponent/47 -> HistoryEvent/8639
				//	HasComponent/47 -> MonitoringFilter/8702
				//	HasComponent/47 -> EventFilter/8708
				//	HasComponent/47 -> AggregateConfiguration/8711
				//	HasComponent/47 -> HistoryEventFieldList/8807
				//	HasComponent/47 -> ScalarTestType/8384
				//	HasComponent/47 -> ArrayTestType/8387
				//	HasComponent/47 -> CompositeTestType/8390
				//	HasComponent/47 -> BuildInfo/8327
				//	HasComponent/47 -> RedundantServerDataType/8843
				//	HasComponent/47 -> EndpointUrlListDataType/11951
				//	HasComponent/47 -> NetworkGroupDataType/11954
				//	HasComponent/47 -> SamplingIntervalDiagnosticsDataType/8846
				//	HasComponent/47 -> ServerDiagnosticsSummaryDataType/8849
				//	HasComponent/47 -> ServerStatusDataType/8852
				//	HasComponent/47 -> SessionDiagnosticsDataType/8855
				//	HasComponent/47 -> SessionSecurityDiagnosticsDataType/8858
				//	HasComponent/47 -> ServiceCounterDataType/8861
				//	HasComponent/47 -> StatusResult/8294
				//	HasComponent/47 -> SubscriptionDiagnosticsDataType/8864
				//	HasComponent/47 -> ModelChangeStructureDataType/8867
				//	HasComponent/47 -> SemanticChangeStructureDataType/8870
				//	HasComponent/47 -> Range/8873
				//	HasComponent/47 -> EUInformation/8876
				//	HasComponent/47 -> ComplexNumberType/12175
				//	HasComponent/47 -> DoubleComplexNumberType/12178
				//	HasComponent/47 -> AxisInformation/12083
				//	HasComponent/47 -> XVType/12086
				//	HasComponent/47 -> ProgramDiagnosticDataType/8882
				//	HasComponent/47 -> Annotation/8879
				//	HasComponent/47 <- XML Schema/92
				//	HasTypeDefinition/40 -> DataTypeDictionaryType/72
				AddDefaultAddressSpaceNodeVariable(8252, "Opc.Ua", "Opc.Ua", "", 0, 0, 0, 0, 0, false, 15, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  8254,  false),
					(47,  8285,  false),
					(47,  8291,  false),
					(47,  8918,  false),
					(47,  8300,  false),
					(47,  8297,  false),
					(47,  8303,  false),
					(47,  8417,  false),
					(47,  8333,  false),
					(47,  8306,  false),
					(47,  8309,  false),
					(47,  8312,  false),
					(47,  8315,  false),
					(47,  8318,  false),
					(47,  8363,  false),
					(47,  8366,  false),
					(47,  8369,  false),
					(47,  8372,  false),
					(47,  8321,  false),
					(47,  8324,  false),
					(47,  8330,  false),
					(47,  8564,  false),
					(47,  8567,  false),
					(47,  8570,  false),
					(47,  8573,  false),
					(47,  8576,  false),
					(47,  8579,  false),
					(47,  8582,  false),
					(47,  8639,  false),
					(47,  8702,  false),
					(47,  8708,  false),
					(47,  8711,  false),
					(47,  8807,  false),
					(47,  8384,  false),
					(47,  8387,  false),
					(47,  8390,  false),
					(47,  8327,  false),
					(47,  8843,  false),
					(47,  11951,  false),
					(47,  11954,  false),
					(47,  8846,  false),
					(47,  8849,  false),
					(47,  8852,  false),
					(47,  8855,  false),
					(47,  8858,  false),
					(47,  8861,  false),
					(47,  8294,  false),
					(47,  8864,  false),
					(47,  8867,  false),
					(47,  8870,  false),
					(47,  8873,  false),
					(47,  8876,  false),
					(47,  12175,  false),
					(47,  12178,  false),
					(47,  12083,  false),
					(47,  12086,  false),
					(47,  8882,  false),
					(47,  8879,  false),
					(47,  92,  true),
					(40,  72,  false),
				});

			}
			private void Part15()
			{

				// NamespaceUri, i=8254, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8254, "NamespaceUri", "NamespaceUri", "A URI that uniquely identifies the dictionary.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  8252,  true),
				});

				// Argument, i=8285, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8285, "Argument", "Argument", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// EnumValueType, i=8291, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8291, "EnumValueType", "EnumValueType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// TimeZoneDataType, i=8918, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8918, "TimeZoneDataType", "TimeZoneDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// ApplicationDescription, i=8300, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8300, "ApplicationDescription", "ApplicationDescription", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// UserTokenPolicy, i=8297, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8297, "UserTokenPolicy", "UserTokenPolicy", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// EndpointDescription, i=8303, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8303, "EndpointDescription", "EndpointDescription", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// RegisteredServer, i=8417, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8417, "RegisteredServer", "RegisteredServer", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// SignedSoftwareCertificate, i=8333, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8333, "SignedSoftwareCertificate", "SignedSoftwareCertificate", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// UserIdentityToken, i=8306, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8306, "UserIdentityToken", "UserIdentityToken", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// AnonymousIdentityToken, i=8309, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8309, "AnonymousIdentityToken", "AnonymousIdentityToken", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// UserNameIdentityToken, i=8312, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8312, "UserNameIdentityToken", "UserNameIdentityToken", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// X509IdentityToken, i=8315, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8315, "X509IdentityToken", "X509IdentityToken", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// IssuedIdentityToken, i=8318, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8318, "IssuedIdentityToken", "IssuedIdentityToken", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// AddNodesItem, i=8363, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8363, "AddNodesItem", "AddNodesItem", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// AddReferencesItem, i=8366, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8366, "AddReferencesItem", "AddReferencesItem", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// DeleteNodesItem, i=8369, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8369, "DeleteNodesItem", "DeleteNodesItem", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// DeleteReferencesItem, i=8372, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8372, "DeleteReferencesItem", "DeleteReferencesItem", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// EndpointConfiguration, i=8321, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8321, "EndpointConfiguration", "EndpointConfiguration", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// SupportedProfile, i=8324, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8324, "SupportedProfile", "SupportedProfile", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// SoftwareCertificate, i=8330, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8330, "SoftwareCertificate", "SoftwareCertificate", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// ContentFilterElement, i=8564, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8564, "ContentFilterElement", "ContentFilterElement", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// ContentFilter, i=8567, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8567, "ContentFilter", "ContentFilter", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// FilterOperand, i=8570, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8570, "FilterOperand", "FilterOperand", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// ElementOperand, i=8573, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8573, "ElementOperand", "ElementOperand", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// LiteralOperand, i=8576, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8576, "LiteralOperand", "LiteralOperand", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// AttributeOperand, i=8579, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8579, "AttributeOperand", "AttributeOperand", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// SimpleAttributeOperand, i=8582, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8582, "SimpleAttributeOperand", "SimpleAttributeOperand", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// HistoryEvent, i=8639, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8639, "HistoryEvent", "HistoryEvent", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// MonitoringFilter, i=8702, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8702, "MonitoringFilter", "MonitoringFilter", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// EventFilter, i=8708, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8708, "EventFilter", "EventFilter", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// AggregateConfiguration, i=8711, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8711, "AggregateConfiguration", "AggregateConfiguration", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// HistoryEventFieldList, i=8807, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8807, "HistoryEventFieldList", "HistoryEventFieldList", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// ScalarTestType, i=8384, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8384, "ScalarTestType", "ScalarTestType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// ArrayTestType, i=8387, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8387, "ArrayTestType", "ArrayTestType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// CompositeTestType, i=8390, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8390, "CompositeTestType", "CompositeTestType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// BuildInfo, i=8327, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8327, "BuildInfo", "BuildInfo", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// RedundantServerDataType, i=8843, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8843, "RedundantServerDataType", "RedundantServerDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// EndpointUrlListDataType, i=11951, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(11951, "EndpointUrlListDataType", "EndpointUrlListDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// NetworkGroupDataType, i=11954, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(11954, "NetworkGroupDataType", "NetworkGroupDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// SamplingIntervalDiagnosticsDataType, i=8846, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8846, "SamplingIntervalDiagnosticsDataType", "SamplingIntervalDiagnosticsDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// ServerDiagnosticsSummaryDataType, i=8849, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8849, "ServerDiagnosticsSummaryDataType", "ServerDiagnosticsSummaryDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// ServerStatusDataType, i=8852, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8852, "ServerStatusDataType", "ServerStatusDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// SessionDiagnosticsDataType, i=8855, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8855, "SessionDiagnosticsDataType", "SessionDiagnosticsDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// SessionSecurityDiagnosticsDataType, i=8858, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8858, "SessionSecurityDiagnosticsDataType", "SessionSecurityDiagnosticsDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// ServiceCounterDataType, i=8861, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8861, "ServiceCounterDataType", "ServiceCounterDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// StatusResult, i=8294, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8294, "StatusResult", "StatusResult", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// SubscriptionDiagnosticsDataType, i=8864, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8864, "SubscriptionDiagnosticsDataType", "SubscriptionDiagnosticsDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// ModelChangeStructureDataType, i=8867, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8867, "ModelChangeStructureDataType", "ModelChangeStructureDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// SemanticChangeStructureDataType, i=8870, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8870, "SemanticChangeStructureDataType", "SemanticChangeStructureDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// Range, i=8873, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8873, "Range", "Range", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// EUInformation, i=8876, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8876, "EUInformation", "EUInformation", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// ComplexNumberType, i=12175, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(12175, "ComplexNumberType", "ComplexNumberType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// DoubleComplexNumberType, i=12178, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(12178, "DoubleComplexNumberType", "DoubleComplexNumberType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// AxisInformation, i=12083, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(12083, "AxisInformation", "AxisInformation", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// XVType, i=12086, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(12086, "XVType", "XVType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// ProgramDiagnosticDataType, i=8882, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8882, "ProgramDiagnosticDataType", "ProgramDiagnosticDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// Annotation, i=8879, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/8252
				AddDefaultAddressSpaceNodeVariable(8879, "Annotation", "Annotation", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  8252,  true),
				});

				// Opc.Ua, i=7617, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasProperty/46 -> NamespaceUri/7619
				//	HasComponent/47 -> Argument/7650
				//	HasComponent/47 -> EnumValueType/7656
				//	HasComponent/47 -> TimeZoneDataType/8914
				//	HasComponent/47 -> ApplicationDescription/7665
				//	HasComponent/47 -> UserTokenPolicy/7662
				//	HasComponent/47 -> EndpointDescription/7668
				//	HasComponent/47 -> RegisteredServer/7782
				//	HasComponent/47 -> SignedSoftwareCertificate/7698
				//	HasComponent/47 -> UserIdentityToken/7671
				//	HasComponent/47 -> AnonymousIdentityToken/7674
				//	HasComponent/47 -> UserNameIdentityToken/7677
				//	HasComponent/47 -> X509IdentityToken/7680
				//	HasComponent/47 -> IssuedIdentityToken/7683
				//	HasComponent/47 -> AddNodesItem/7728
				//	HasComponent/47 -> AddReferencesItem/7731
				//	HasComponent/47 -> DeleteNodesItem/7734
				//	HasComponent/47 -> DeleteReferencesItem/7737
				//	HasComponent/47 -> EndpointConfiguration/7686
				//	HasComponent/47 -> SupportedProfile/7689
				//	HasComponent/47 -> SoftwareCertificate/7695
				//	HasComponent/47 -> ContentFilterElement/7929
				//	HasComponent/47 -> ContentFilter/7932
				//	HasComponent/47 -> FilterOperand/7935
				//	HasComponent/47 -> ElementOperand/7938
				//	HasComponent/47 -> LiteralOperand/7941
				//	HasComponent/47 -> AttributeOperand/7944
				//	HasComponent/47 -> SimpleAttributeOperand/7947
				//	HasComponent/47 -> HistoryEvent/8004
				//	HasComponent/47 -> MonitoringFilter/8067
				//	HasComponent/47 -> EventFilter/8073
				//	HasComponent/47 -> AggregateConfiguration/8076
				//	HasComponent/47 -> HistoryEventFieldList/8172
				//	HasComponent/47 -> ScalarTestType/7749
				//	HasComponent/47 -> ArrayTestType/7752
				//	HasComponent/47 -> CompositeTestType/7755
				//	HasComponent/47 -> BuildInfo/7692
				//	HasComponent/47 -> RedundantServerDataType/8208
				//	HasComponent/47 -> EndpointUrlListDataType/11959
				//	HasComponent/47 -> NetworkGroupDataType/11962
				//	HasComponent/47 -> SamplingIntervalDiagnosticsDataType/8211
				//	HasComponent/47 -> ServerDiagnosticsSummaryDataType/8214
				//	HasComponent/47 -> ServerStatusDataType/8217
				//	HasComponent/47 -> SessionDiagnosticsDataType/8220
				//	HasComponent/47 -> SessionSecurityDiagnosticsDataType/8223
				//	HasComponent/47 -> ServiceCounterDataType/8226
				//	HasComponent/47 -> StatusResult/7659
				//	HasComponent/47 -> SubscriptionDiagnosticsDataType/8229
				//	HasComponent/47 -> ModelChangeStructureDataType/8232
				//	HasComponent/47 -> SemanticChangeStructureDataType/8235
				//	HasComponent/47 -> Range/8238
				//	HasComponent/47 -> EUInformation/8241
				//	HasComponent/47 -> ComplexNumberType/12183
				//	HasComponent/47 -> DoubleComplexNumberType/12186
				//	HasComponent/47 -> AxisInformation/12091
				//	HasComponent/47 -> XVType/12094
				//	HasComponent/47 -> ProgramDiagnosticDataType/8247
				//	HasComponent/47 -> Annotation/8244
				//	HasComponent/47 <- OPC Binary/93
				//	HasTypeDefinition/40 -> DataTypeDictionaryType/72
				AddDefaultAddressSpaceNodeVariable(7617, "Opc.Ua", "Opc.Ua", "", 0, 0, 0, 0, 0, false, 15, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  7619,  false),
					(47,  7650,  false),
					(47,  7656,  false),
					(47,  8914,  false),
					(47,  7665,  false),
					(47,  7662,  false),
					(47,  7668,  false),
					(47,  7782,  false),
					(47,  7698,  false),
					(47,  7671,  false),
					(47,  7674,  false),
					(47,  7677,  false),
					(47,  7680,  false),
					(47,  7683,  false),
					(47,  7728,  false),
					(47,  7731,  false),
					(47,  7734,  false),
					(47,  7737,  false),
					(47,  7686,  false),
					(47,  7689,  false),
					(47,  7695,  false),
					(47,  7929,  false),
					(47,  7932,  false),
					(47,  7935,  false),
					(47,  7938,  false),
					(47,  7941,  false),
					(47,  7944,  false),
					(47,  7947,  false),
					(47,  8004,  false),
					(47,  8067,  false),
					(47,  8073,  false),
					(47,  8076,  false),
					(47,  8172,  false),
					(47,  7749,  false),
					(47,  7752,  false),
					(47,  7755,  false),
					(47,  7692,  false),
					(47,  8208,  false),
					(47,  11959,  false),
					(47,  11962,  false),
					(47,  8211,  false),
					(47,  8214,  false),
					(47,  8217,  false),
					(47,  8220,  false),
					(47,  8223,  false),
					(47,  8226,  false),
					(47,  7659,  false),
					(47,  8229,  false),
					(47,  8232,  false),
					(47,  8235,  false),
					(47,  8238,  false),
					(47,  8241,  false),
					(47,  12183,  false),
					(47,  12186,  false),
					(47,  12091,  false),
					(47,  12094,  false),
					(47,  8247,  false),
					(47,  8244,  false),
					(47,  93,  true),
					(40,  72,  false),
				});

				// NamespaceUri, i=7619, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> PropertyType/68
				//	HasProperty/46 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7619, "NamespaceUri", "NamespaceUri", "A URI that uniquely identifies the dictionary.", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  68,  false),
					(46,  7617,  true),
				});

				// Argument, i=7650, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7650, "Argument", "Argument", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// EnumValueType, i=7656, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7656, "EnumValueType", "EnumValueType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// TimeZoneDataType, i=8914, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8914, "TimeZoneDataType", "TimeZoneDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// ApplicationDescription, i=7665, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7665, "ApplicationDescription", "ApplicationDescription", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// UserTokenPolicy, i=7662, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7662, "UserTokenPolicy", "UserTokenPolicy", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// EndpointDescription, i=7668, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7668, "EndpointDescription", "EndpointDescription", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// RegisteredServer, i=7782, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7782, "RegisteredServer", "RegisteredServer", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// SignedSoftwareCertificate, i=7698, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7698, "SignedSoftwareCertificate", "SignedSoftwareCertificate", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// UserIdentityToken, i=7671, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7671, "UserIdentityToken", "UserIdentityToken", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// AnonymousIdentityToken, i=7674, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7674, "AnonymousIdentityToken", "AnonymousIdentityToken", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// UserNameIdentityToken, i=7677, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7677, "UserNameIdentityToken", "UserNameIdentityToken", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// X509IdentityToken, i=7680, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7680, "X509IdentityToken", "X509IdentityToken", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// IssuedIdentityToken, i=7683, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7683, "IssuedIdentityToken", "IssuedIdentityToken", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// AddNodesItem, i=7728, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7728, "AddNodesItem", "AddNodesItem", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// AddReferencesItem, i=7731, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7731, "AddReferencesItem", "AddReferencesItem", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// DeleteNodesItem, i=7734, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7734, "DeleteNodesItem", "DeleteNodesItem", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// DeleteReferencesItem, i=7737, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7737, "DeleteReferencesItem", "DeleteReferencesItem", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// EndpointConfiguration, i=7686, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7686, "EndpointConfiguration", "EndpointConfiguration", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// SupportedProfile, i=7689, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7689, "SupportedProfile", "SupportedProfile", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// SoftwareCertificate, i=7695, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7695, "SoftwareCertificate", "SoftwareCertificate", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// ContentFilterElement, i=7929, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7929, "ContentFilterElement", "ContentFilterElement", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// ContentFilter, i=7932, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7932, "ContentFilter", "ContentFilter", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// FilterOperand, i=7935, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7935, "FilterOperand", "FilterOperand", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// ElementOperand, i=7938, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7938, "ElementOperand", "ElementOperand", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// LiteralOperand, i=7941, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7941, "LiteralOperand", "LiteralOperand", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// AttributeOperand, i=7944, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7944, "AttributeOperand", "AttributeOperand", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// SimpleAttributeOperand, i=7947, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7947, "SimpleAttributeOperand", "SimpleAttributeOperand", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// HistoryEvent, i=8004, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8004, "HistoryEvent", "HistoryEvent", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// MonitoringFilter, i=8067, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8067, "MonitoringFilter", "MonitoringFilter", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// EventFilter, i=8073, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8073, "EventFilter", "EventFilter", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// AggregateConfiguration, i=8076, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8076, "AggregateConfiguration", "AggregateConfiguration", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// HistoryEventFieldList, i=8172, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8172, "HistoryEventFieldList", "HistoryEventFieldList", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// ScalarTestType, i=7749, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7749, "ScalarTestType", "ScalarTestType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// ArrayTestType, i=7752, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7752, "ArrayTestType", "ArrayTestType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// CompositeTestType, i=7755, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7755, "CompositeTestType", "CompositeTestType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// BuildInfo, i=7692, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7692, "BuildInfo", "BuildInfo", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// RedundantServerDataType, i=8208, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8208, "RedundantServerDataType", "RedundantServerDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// EndpointUrlListDataType, i=11959, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(11959, "EndpointUrlListDataType", "EndpointUrlListDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// NetworkGroupDataType, i=11962, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(11962, "NetworkGroupDataType", "NetworkGroupDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// SamplingIntervalDiagnosticsDataType, i=8211, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8211, "SamplingIntervalDiagnosticsDataType", "SamplingIntervalDiagnosticsDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// ServerDiagnosticsSummaryDataType, i=8214, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8214, "ServerDiagnosticsSummaryDataType", "ServerDiagnosticsSummaryDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// ServerStatusDataType, i=8217, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8217, "ServerStatusDataType", "ServerStatusDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// SessionDiagnosticsDataType, i=8220, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8220, "SessionDiagnosticsDataType", "SessionDiagnosticsDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// SessionSecurityDiagnosticsDataType, i=8223, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8223, "SessionSecurityDiagnosticsDataType", "SessionSecurityDiagnosticsDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// ServiceCounterDataType, i=8226, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8226, "ServiceCounterDataType", "ServiceCounterDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// StatusResult, i=7659, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(7659, "StatusResult", "StatusResult", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// SubscriptionDiagnosticsDataType, i=8229, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8229, "SubscriptionDiagnosticsDataType", "SubscriptionDiagnosticsDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// ModelChangeStructureDataType, i=8232, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8232, "ModelChangeStructureDataType", "ModelChangeStructureDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// SemanticChangeStructureDataType, i=8235, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8235, "SemanticChangeStructureDataType", "SemanticChangeStructureDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// Range, i=8238, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8238, "Range", "Range", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// EUInformation, i=8241, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8241, "EUInformation", "EUInformation", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});


			}
			private void Part16()
			{
				// ComplexNumberType, i=12183, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(12183, "ComplexNumberType", "ComplexNumberType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// DoubleComplexNumberType, i=12186, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(12186, "DoubleComplexNumberType", "DoubleComplexNumberType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// AxisInformation, i=12091, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(12091, "AxisInformation", "AxisInformation", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// XVType, i=12094, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(12094, "XVType", "XVType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// ProgramDiagnosticDataType, i=8247, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8247, "ProgramDiagnosticDataType", "ProgramDiagnosticDataType", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// Annotation, i=8244, TypeGenerator.AddressSpaceGenerator+NodeVariable
				//	HasTypeDefinition/40 -> DataTypeDescriptionType/69
				//	HasComponent/47 <- Opc.Ua/7617
				AddDefaultAddressSpaceNodeVariable(8244, "Annotation", "Annotation", "", 0, 0, 0, 0, 0, false, 12, new (uint referenceType, uint target, bool isInverse)[] {
					(40,  69,  false),
					(47,  7617,  true),
				});

				// BaseVariableType, i=62, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasSubtype/45 -> BaseDataVariableType/63
				//	HasSubtype/45 -> PropertyType/68
				AddDefaultAddressSpaceNodeVariableType(62, "BaseVariableType", "BaseVariableType", "The abstract base type for all variable nodes.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  63,  false),
					(45,  68,  false),
				});

				// BaseDataVariableType, i=63, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasSubtype/45 <- BaseVariableType/62
				//	HasSubtype/45 -> DataTypeDescriptionType/69
				//	HasSubtype/45 -> DataTypeDictionaryType/72
				//	HasSubtype/45 -> ServerVendorCapabilityType/2137
				//	HasSubtype/45 -> ServerStatusType/2138
				//	HasSubtype/45 -> BuildInfoType/3051
				//	HasSubtype/45 -> ServerDiagnosticsSummaryType/2150
				//	HasSubtype/45 -> SamplingIntervalDiagnosticsArrayType/2164
				//	HasSubtype/45 -> SamplingIntervalDiagnosticsType/2165
				//	HasSubtype/45 -> SubscriptionDiagnosticsArrayType/2171
				//	HasSubtype/45 -> SubscriptionDiagnosticsType/2172
				//	HasSubtype/45 -> SessionDiagnosticsArrayType/2196
				//	HasSubtype/45 -> SessionDiagnosticsVariableType/2197
				//	HasSubtype/45 -> SessionSecurityDiagnosticsArrayType/2243
				//	HasSubtype/45 -> SessionSecurityDiagnosticsType/2244
				//	HasSubtype/45 -> OptionSetType/11487
				//	HasSubtype/45 -> StateVariableType/2755
				//	HasSubtype/45 -> TransitionVariableType/2762
				//	HasSubtype/45 -> DataItemType/2365
				//	HasSubtype/45 -> ConditionVariableType/9002
				//	HasSubtype/45 -> ProgramDiagnosticType/2380
				AddDefaultAddressSpaceNodeVariableType(63, "BaseDataVariableType", "BaseDataVariableType", "The type for variable that represents a process value.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  62,  true),
					(45,  69,  false),
					(45,  72,  false),
					(45,  2137,  false),
					(45,  2138,  false),
					(45,  3051,  false),
					(45,  2150,  false),
					(45,  2164,  false),
					(45,  2165,  false),
					(45,  2171,  false),
					(45,  2172,  false),
					(45,  2196,  false),
					(45,  2197,  false),
					(45,  2243,  false),
					(45,  2244,  false),
					(45,  11487,  false),
					(45,  2755,  false),
					(45,  2762,  false),
					(45,  2365,  false),
					(45,  9002,  false),
					(45,  2380,  false),
				});

				// PropertyType, i=68, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasSubtype/45 <- BaseVariableType/62
				AddDefaultAddressSpaceNodeVariableType(68, "PropertyType", "PropertyType", "The type for variable that represents a property of another node.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  62,  true),
				});

				// DataTypeDescriptionType, i=69, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> DataTypeVersion/104
				//	HasProperty/46 -> DictionaryFragment/105
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(69, "DataTypeDescriptionType", "DataTypeDescriptionType", "The type for variable that represents the description of a data type encoding.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  104,  false),
					(46,  105,  false),
					(45,  63,  true),
				});

				// DataTypeDictionaryType, i=72, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> DataTypeVersion/106
				//	HasProperty/46 -> NamespaceUri/107
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(72, "DataTypeDictionaryType", "DataTypeDictionaryType", "The type for variable that represents the collection of data type decriptions.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  106,  false),
					(46,  107,  false),
					(45,  63,  true),
				});

				// ServerVendorCapabilityType, i=2137, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(2137, "ServerVendorCapabilityType", "ServerVendorCapabilityType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  63,  true),
				});

				// ServerStatusType, i=2138, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasComponent/47 -> StartTime/2139
				//	HasComponent/47 -> CurrentTime/2140
				//	HasComponent/47 -> State/2141
				//	HasComponent/47 -> BuildInfo/2142
				//	HasComponent/47 -> SecondsTillShutdown/2752
				//	HasComponent/47 -> ShutdownReason/2753
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(2138, "ServerStatusType", "ServerStatusType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2139,  false),
					(47,  2140,  false),
					(47,  2141,  false),
					(47,  2142,  false),
					(47,  2752,  false),
					(47,  2753,  false),
					(45,  63,  true),
				});

				// BuildInfoType, i=3051, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasComponent/47 -> ProductUri/3052
				//	HasComponent/47 -> ManufacturerName/3053
				//	HasComponent/47 -> ProductName/3054
				//	HasComponent/47 -> SoftwareVersion/3055
				//	HasComponent/47 -> BuildNumber/3056
				//	HasComponent/47 -> BuildDate/3057
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(3051, "BuildInfoType", "BuildInfoType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  3052,  false),
					(47,  3053,  false),
					(47,  3054,  false),
					(47,  3055,  false),
					(47,  3056,  false),
					(47,  3057,  false),
					(45,  63,  true),
				});

				// ServerDiagnosticsSummaryType, i=2150, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasComponent/47 -> ServerViewCount/2151
				//	HasComponent/47 -> CurrentSessionCount/2152
				//	HasComponent/47 -> CumulatedSessionCount/2153
				//	HasComponent/47 -> SecurityRejectedSessionCount/2154
				//	HasComponent/47 -> RejectedSessionCount/2155
				//	HasComponent/47 -> SessionTimeoutCount/2156
				//	HasComponent/47 -> SessionAbortCount/2157
				//	HasComponent/47 -> PublishingIntervalCount/2159
				//	HasComponent/47 -> CurrentSubscriptionCount/2160
				//	HasComponent/47 -> CumulatedSubscriptionCount/2161
				//	HasComponent/47 -> SecurityRejectedRequestsCount/2162
				//	HasComponent/47 -> RejectedRequestsCount/2163
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(2150, "ServerDiagnosticsSummaryType", "ServerDiagnosticsSummaryType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2151,  false),
					(47,  2152,  false),
					(47,  2153,  false),
					(47,  2154,  false),
					(47,  2155,  false),
					(47,  2156,  false),
					(47,  2157,  false),
					(47,  2159,  false),
					(47,  2160,  false),
					(47,  2161,  false),
					(47,  2162,  false),
					(47,  2163,  false),
					(45,  63,  true),
				});

				// SamplingIntervalDiagnosticsArrayType, i=2164, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(2164, "SamplingIntervalDiagnosticsArrayType", "SamplingIntervalDiagnosticsArrayType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  63,  true),
				});

				// SamplingIntervalDiagnosticsType, i=2165, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasComponent/47 -> SamplingInterval/2166
				//	HasComponent/47 -> SampledMonitoredItemsCount/11697
				//	HasComponent/47 -> MaxSampledMonitoredItemsCount/11698
				//	HasComponent/47 -> DisabledMonitoredItemsSamplingCount/11699
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(2165, "SamplingIntervalDiagnosticsType", "SamplingIntervalDiagnosticsType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2166,  false),
					(47,  11697,  false),
					(47,  11698,  false),
					(47,  11699,  false),
					(45,  63,  true),
				});

				// SubscriptionDiagnosticsArrayType, i=2171, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(2171, "SubscriptionDiagnosticsArrayType", "SubscriptionDiagnosticsArrayType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  63,  true),
				});

				// SubscriptionDiagnosticsType, i=2172, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasComponent/47 -> SessionId/2173
				//	HasComponent/47 -> SubscriptionId/2174
				//	HasComponent/47 -> Priority/2175
				//	HasComponent/47 -> PublishingInterval/2176
				//	HasComponent/47 -> MaxKeepAliveCount/2177
				//	HasComponent/47 -> MaxLifetimeCount/8888
				//	HasComponent/47 -> MaxNotificationsPerPublish/2179
				//	HasComponent/47 -> PublishingEnabled/2180
				//	HasComponent/47 -> ModifyCount/2181
				//	HasComponent/47 -> EnableCount/2182
				//	HasComponent/47 -> DisableCount/2183
				//	HasComponent/47 -> RepublishRequestCount/2184
				//	HasComponent/47 -> RepublishMessageRequestCount/2185
				//	HasComponent/47 -> RepublishMessageCount/2186
				//	HasComponent/47 -> TransferRequestCount/2187
				//	HasComponent/47 -> TransferredToAltClientCount/2188
				//	HasComponent/47 -> TransferredToSameClientCount/2189
				//	HasComponent/47 -> PublishRequestCount/2190
				//	HasComponent/47 -> DataChangeNotificationsCount/2191
				//	HasComponent/47 -> EventNotificationsCount/2998
				//	HasComponent/47 -> NotificationsCount/2193
				//	HasComponent/47 -> LatePublishRequestCount/8889
				//	HasComponent/47 -> CurrentKeepAliveCount/8890
				//	HasComponent/47 -> CurrentLifetimeCount/8891
				//	HasComponent/47 -> UnacknowledgedMessageCount/8892
				//	HasComponent/47 -> DiscardedMessageCount/8893
				//	HasComponent/47 -> MonitoredItemCount/8894
				//	HasComponent/47 -> DisabledMonitoredItemCount/8895
				//	HasComponent/47 -> MonitoringQueueOverflowCount/8896
				//	HasComponent/47 -> NextSequenceNumber/8897
				//	HasComponent/47 -> EventQueueOverFlowCount/8902
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(2172, "SubscriptionDiagnosticsType", "SubscriptionDiagnosticsType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2173,  false),
					(47,  2174,  false),
					(47,  2175,  false),
					(47,  2176,  false),
					(47,  2177,  false),
					(47,  8888,  false),
					(47,  2179,  false),
					(47,  2180,  false),
					(47,  2181,  false),
					(47,  2182,  false),
					(47,  2183,  false),
					(47,  2184,  false),
					(47,  2185,  false),
					(47,  2186,  false),
					(47,  2187,  false),
					(47,  2188,  false),
					(47,  2189,  false),
					(47,  2190,  false),
					(47,  2191,  false),
					(47,  2998,  false),
					(47,  2193,  false),
					(47,  8889,  false),
					(47,  8890,  false),
					(47,  8891,  false),
					(47,  8892,  false),
					(47,  8893,  false),
					(47,  8894,  false),
					(47,  8895,  false),
					(47,  8896,  false),
					(47,  8897,  false),
					(47,  8902,  false),
					(45,  63,  true),
				});

				// SessionDiagnosticsArrayType, i=2196, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(2196, "SessionDiagnosticsArrayType", "SessionDiagnosticsArrayType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  63,  true),
				});

				// SessionDiagnosticsVariableType, i=2197, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasComponent/47 -> SessionId/2198
				//	HasComponent/47 -> SessionName/2199
				//	HasComponent/47 -> ClientDescription/2200
				//	HasComponent/47 -> ServerUri/2201
				//	HasComponent/47 -> EndpointUrl/2202
				//	HasComponent/47 -> LocaleIds/2203
				//	HasComponent/47 -> ActualSessionTimeout/2204
				//	HasComponent/47 -> MaxResponseMessageSize/3050
				//	HasComponent/47 -> ClientConnectionTime/2205
				//	HasComponent/47 -> ClientLastContactTime/2206
				//	HasComponent/47 -> CurrentSubscriptionsCount/2207
				//	HasComponent/47 -> CurrentMonitoredItemsCount/2208
				//	HasComponent/47 -> CurrentPublishRequestsInQueue/2209
				//	HasComponent/47 -> TotalRequestCount/8900
				//	HasComponent/47 -> UnauthorizedRequestCount/11892
				//	HasComponent/47 -> ReadCount/2217
				//	HasComponent/47 -> HistoryReadCount/2218
				//	HasComponent/47 -> WriteCount/2219
				//	HasComponent/47 -> HistoryUpdateCount/2220
				//	HasComponent/47 -> CallCount/2221
				//	HasComponent/47 -> CreateMonitoredItemsCount/2222
				//	HasComponent/47 -> ModifyMonitoredItemsCount/2223
				//	HasComponent/47 -> SetMonitoringModeCount/2224
				//	HasComponent/47 -> SetTriggeringCount/2225
				//	HasComponent/47 -> DeleteMonitoredItemsCount/2226
				//	HasComponent/47 -> CreateSubscriptionCount/2227
				//	HasComponent/47 -> ModifySubscriptionCount/2228
				//	HasComponent/47 -> SetPublishingModeCount/2229
				//	HasComponent/47 -> PublishCount/2230
				//	HasComponent/47 -> RepublishCount/2231
				//	HasComponent/47 -> TransferSubscriptionsCount/2232
				//	HasComponent/47 -> DeleteSubscriptionsCount/2233
				//	HasComponent/47 -> AddNodesCount/2234
				//	HasComponent/47 -> AddReferencesCount/2235
				//	HasComponent/47 -> DeleteNodesCount/2236
				//	HasComponent/47 -> DeleteReferencesCount/2237
				//	HasComponent/47 -> BrowseCount/2238
				//	HasComponent/47 -> BrowseNextCount/2239
				//	HasComponent/47 -> TranslateBrowsePathsToNodeIdsCount/2240
				//	HasComponent/47 -> QueryFirstCount/2241
				//	HasComponent/47 -> QueryNextCount/2242
				//	HasComponent/47 -> RegisterNodesCount/2730
				//	HasComponent/47 -> UnregisterNodesCount/2731
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(2197, "SessionDiagnosticsVariableType", "SessionDiagnosticsVariableType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2198,  false),
					(47,  2199,  false),
					(47,  2200,  false),
					(47,  2201,  false),
					(47,  2202,  false),
					(47,  2203,  false),
					(47,  2204,  false),
					(47,  3050,  false),
					(47,  2205,  false),
					(47,  2206,  false),
					(47,  2207,  false),
					(47,  2208,  false),
					(47,  2209,  false),
					(47,  8900,  false),
					(47,  11892,  false),
					(47,  2217,  false),
					(47,  2218,  false),
					(47,  2219,  false),
					(47,  2220,  false),
					(47,  2221,  false),
					(47,  2222,  false),
					(47,  2223,  false),
					(47,  2224,  false),
					(47,  2225,  false),
					(47,  2226,  false),
					(47,  2227,  false),
					(47,  2228,  false),
					(47,  2229,  false),
					(47,  2230,  false),
					(47,  2231,  false),
					(47,  2232,  false),
					(47,  2233,  false),
					(47,  2234,  false),
					(47,  2235,  false),
					(47,  2236,  false),
					(47,  2237,  false),
					(47,  2238,  false),
					(47,  2239,  false),
					(47,  2240,  false),
					(47,  2241,  false),
					(47,  2242,  false),
					(47,  2730,  false),
					(47,  2731,  false),
					(45,  63,  true),
				});

				// SessionSecurityDiagnosticsArrayType, i=2243, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(2243, "SessionSecurityDiagnosticsArrayType", "SessionSecurityDiagnosticsArrayType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  63,  true),
				});

				// SessionSecurityDiagnosticsType, i=2244, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasComponent/47 -> SessionId/2245
				//	HasComponent/47 -> ClientUserIdOfSession/2246
				//	HasComponent/47 -> ClientUserIdHistory/2247
				//	HasComponent/47 -> AuthenticationMechanism/2248
				//	HasComponent/47 -> Encoding/2249
				//	HasComponent/47 -> TransportProtocol/2250
				//	HasComponent/47 -> SecurityMode/2251
				//	HasComponent/47 -> SecurityPolicyUri/2252
				//	HasComponent/47 -> ClientCertificate/3058
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(2244, "SessionSecurityDiagnosticsType", "SessionSecurityDiagnosticsType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  2245,  false),
					(47,  2246,  false),
					(47,  2247,  false),
					(47,  2248,  false),
					(47,  2249,  false),
					(47,  2250,  false),
					(47,  2251,  false),
					(47,  2252,  false),
					(47,  3058,  false),
					(45,  63,  true),
				});

				// OptionSetType, i=11487, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> OptionSetValues/11488
				//	HasProperty/46 -> BitMask/11701
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(11487, "OptionSetType", "OptionSetType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11488,  false),
					(46,  11701,  false),
					(45,  63,  true),
				});

				// StateVariableType, i=2755, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> Id/2756
				//	HasProperty/46 -> Name/2757
				//	HasProperty/46 -> Number/2758
				//	HasProperty/46 -> EffectiveDisplayName/2759
				//	HasSubtype/45 <- BaseDataVariableType/63
				//	HasSubtype/45 -> FiniteStateVariableType/2760
				//	HasSubtype/45 -> TwoStateVariableType/8995
				AddDefaultAddressSpaceNodeVariableType(2755, "StateVariableType", "StateVariableType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2756,  false),
					(46,  2757,  false),
					(46,  2758,  false),
					(46,  2759,  false),
					(45,  63,  true),
					(45,  2760,  false),
					(45,  8995,  false),
				});

				// TransitionVariableType, i=2762, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> Id/2763
				//	HasProperty/46 -> Name/2764
				//	HasProperty/46 -> Number/2765
				//	HasProperty/46 -> TransitionTime/2766
				//	HasProperty/46 -> EffectiveTransitionTime/11456
				//	HasSubtype/45 <- BaseDataVariableType/63
				//	HasSubtype/45 -> FiniteTransitionVariableType/2767
				AddDefaultAddressSpaceNodeVariableType(2762, "TransitionVariableType", "TransitionVariableType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2763,  false),
					(46,  2764,  false),
					(46,  2765,  false),
					(46,  2766,  false),
					(46,  11456,  false),
					(45,  63,  true),
					(45,  2767,  false),
				});

				// FiniteStateVariableType, i=2760, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> Id/2761
				//	HasSubtype/45 <- StateVariableType/2755
				AddDefaultAddressSpaceNodeVariableType(2760, "FiniteStateVariableType", "FiniteStateVariableType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2761,  false),
					(45,  2755,  true),
				});

				// FiniteTransitionVariableType, i=2767, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> Id/2768
				//	HasSubtype/45 <- TransitionVariableType/2762
				AddDefaultAddressSpaceNodeVariableType(2767, "FiniteTransitionVariableType", "FiniteTransitionVariableType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2768,  false),
					(45,  2762,  true),
				});

				// DataItemType, i=2365, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> Definition/2366
				//	HasProperty/46 -> ValuePrecision/2367
				//	HasSubtype/45 <- BaseDataVariableType/63
				//	HasSubtype/45 -> AnalogItemType/2368
				//	HasSubtype/45 -> DiscreteItemType/2372
				//	HasSubtype/45 -> ArrayItemType/12021
				AddDefaultAddressSpaceNodeVariableType(2365, "DataItemType", "DataItemType", "A variable that contains live automation data.", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2366,  false),
					(46,  2367,  false),
					(45,  63,  true),
					(45,  2368,  false),
					(45,  2372,  false),
					(45,  12021,  false),
				});

				// AnalogItemType, i=2368, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> InstrumentRange/2370
				//	HasProperty/46 -> EURange/2369
				//	HasProperty/46 -> EngineeringUnits/2371
				//	HasSubtype/45 <- DataItemType/2365
				AddDefaultAddressSpaceNodeVariableType(2368, "AnalogItemType", "AnalogItemType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2370,  false),
					(46,  2369,  false),
					(46,  2371,  false),
					(45,  2365,  true),
				});

				// DiscreteItemType, i=2372, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasSubtype/45 <- DataItemType/2365
				//	HasSubtype/45 -> TwoStateDiscreteType/2373
				//	HasSubtype/45 -> MultiStateDiscreteType/2376
				//	HasSubtype/45 -> MultiStateValueDiscreteType/11238
				AddDefaultAddressSpaceNodeVariableType(2372, "DiscreteItemType", "DiscreteItemType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(45,  2365,  true),
					(45,  2373,  false),
					(45,  2376,  false),
					(45,  11238,  false),
				});

				// TwoStateDiscreteType, i=2373, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> FalseState/2374
				//	HasProperty/46 -> TrueState/2375
				//	HasSubtype/45 <- DiscreteItemType/2372
				AddDefaultAddressSpaceNodeVariableType(2373, "TwoStateDiscreteType", "TwoStateDiscreteType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2374,  false),
					(46,  2375,  false),
					(45,  2372,  true),
				});

				// MultiStateDiscreteType, i=2376, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> EnumStrings/2377
				//	HasSubtype/45 <- DiscreteItemType/2372
				AddDefaultAddressSpaceNodeVariableType(2376, "MultiStateDiscreteType", "MultiStateDiscreteType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2377,  false),
					(45,  2372,  true),
				});

				// MultiStateValueDiscreteType, i=11238, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> EnumValues/11241
				//	HasProperty/46 -> ValueAsText/11461
				//	HasSubtype/45 <- DiscreteItemType/2372
				AddDefaultAddressSpaceNodeVariableType(11238, "MultiStateValueDiscreteType", "MultiStateValueDiscreteType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11241,  false),
					(46,  11461,  false),
					(45,  2372,  true),
				});

				// ArrayItemType, i=12021, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> InstrumentRange/12024
				//	HasProperty/46 -> EURange/12025
				//	HasProperty/46 -> EngineeringUnits/12026
				//	HasProperty/46 -> Title/12027
				//	HasProperty/46 -> AxisScaleType/12028
				//	HasSubtype/45 <- DataItemType/2365
				//	HasSubtype/45 -> YArrayItemType/12029
				//	HasSubtype/45 -> XYArrayItemType/12038
				//	HasSubtype/45 -> ImageItemType/12047
				//	HasSubtype/45 -> CubeItemType/12057
				//	HasSubtype/45 -> NDimensionArrayItemType/12068
				AddDefaultAddressSpaceNodeVariableType(12021, "ArrayItemType", "ArrayItemType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  12024,  false),
					(46,  12025,  false),
					(46,  12026,  false),
					(46,  12027,  false),
					(46,  12028,  false),
					(45,  2365,  true),
					(45,  12029,  false),
					(45,  12038,  false),
					(45,  12047,  false),
					(45,  12057,  false),
					(45,  12068,  false),
				});

				// YArrayItemType, i=12029, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> XAxisDefinition/12037
				//	HasSubtype/45 <- ArrayItemType/12021
				AddDefaultAddressSpaceNodeVariableType(12029, "YArrayItemType", "YArrayItemType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  12037,  false),
					(45,  12021,  true),
				});

				// XYArrayItemType, i=12038, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> XAxisDefinition/12046
				//	HasSubtype/45 <- ArrayItemType/12021
				AddDefaultAddressSpaceNodeVariableType(12038, "XYArrayItemType", "XYArrayItemType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  12046,  false),
					(45,  12021,  true),
				});

				// ImageItemType, i=12047, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> XAxisDefinition/12055
				//	HasProperty/46 -> YAxisDefinition/12056
				//	HasSubtype/45 <- ArrayItemType/12021
				AddDefaultAddressSpaceNodeVariableType(12047, "ImageItemType", "ImageItemType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  12055,  false),
					(46,  12056,  false),
					(45,  12021,  true),
				});

				// CubeItemType, i=12057, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> XAxisDefinition/12065
				//	HasProperty/46 -> YAxisDefinition/12066
				//	HasProperty/46 -> ZAxisDefinition/12067
				//	HasSubtype/45 <- ArrayItemType/12021
				AddDefaultAddressSpaceNodeVariableType(12057, "CubeItemType", "CubeItemType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  12065,  false),
					(46,  12066,  false),
					(46,  12067,  false),
					(45,  12021,  true),
				});

				// NDimensionArrayItemType, i=12068, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> AxisDefinition/12076
				//	HasSubtype/45 <- ArrayItemType/12021
				AddDefaultAddressSpaceNodeVariableType(12068, "NDimensionArrayItemType", "NDimensionArrayItemType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  12076,  false),
					(45,  12021,  true),
				});

				// TwoStateVariableType, i=8995, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> Id/8996
				//	HasProperty/46 -> TransitionTime/9000
				//	HasProperty/46 -> EffectiveTransitionTime/9001
				//	HasProperty/46 -> TrueState/11110
				//	HasProperty/46 -> FalseState/11111
				//	HasSubtype/45 <- StateVariableType/2755
				AddDefaultAddressSpaceNodeVariableType(8995, "TwoStateVariableType", "TwoStateVariableType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  8996,  false),
					(46,  9000,  false),
					(46,  9001,  false),
					(46,  11110,  false),
					(46,  11111,  false),
					(45,  2755,  true),
				});

				// ConditionVariableType, i=9002, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> SourceTimestamp/9003
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(9002, "ConditionVariableType", "ConditionVariableType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9003,  false),
					(45,  63,  true),
				});

				// ProgramDiagnosticType, i=2380, TypeGenerator.AddressSpaceGenerator+NodeVariableType
				//	HasProperty/46 -> CreateSessionId/2381
				//	HasProperty/46 -> CreateClientName/2382
				//	HasProperty/46 -> InvocationCreationTime/2383
				//	HasProperty/46 -> LastTransitionTime/2384
				//	HasProperty/46 -> LastMethodCall/2385
				//	HasProperty/46 -> LastMethodSessionId/2386
				//	HasProperty/46 -> LastMethodInputArguments/2387
				//	HasProperty/46 -> LastMethodOutputArguments/2388
				//	HasProperty/46 -> LastMethodCallTime/2389
				//	HasProperty/46 -> LastMethodReturnStatus/2390
				//	HasSubtype/45 <- BaseDataVariableType/63
				AddDefaultAddressSpaceNodeVariableType(2380, "ProgramDiagnosticType", "ProgramDiagnosticType", "", 0, 0, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2381,  false),
					(46,  2382,  false),
					(46,  2383,  false),
					(46,  2384,  false),
					(46,  2385,  false),
					(46,  2386,  false),
					(46,  2387,  false),
					(46,  2388,  false),
					(46,  2389,  false),
					(46,  2390,  false),
					(45,  63,  true),
				});

				// GetMonitoredItems, i=11489, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11490
				//	HasProperty/46 -> OutputArguments/11491
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- ServerType/2004
				AddDefaultAddressSpaceNodeMethod(11489, "GetMonitoredItems", "GetMonitoredItems", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11490,  false),
					(46,  11491,  false),
					(37,  80,  false),
					(47,  2004,  true),
				});

				// Open, i=11580, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11581
				//	HasProperty/46 -> OutputArguments/11582
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- FileType/11575
				AddDefaultAddressSpaceNodeMethod(11580, "Open", "Open", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11581,  false),
					(46,  11582,  false),
					(37,  78,  false),
					(47,  11575,  true),
				});

				// Close, i=11583, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11584
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- FileType/11575
				AddDefaultAddressSpaceNodeMethod(11583, "Close", "Close", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11584,  false),
					(37,  78,  false),
					(47,  11575,  true),
				});

				// Read, i=11585, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11586
				//	HasProperty/46 -> OutputArguments/11587
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- FileType/11575
				AddDefaultAddressSpaceNodeMethod(11585, "Read", "Read", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11586,  false),
					(46,  11587,  false),
					(37,  78,  false),
					(47,  11575,  true),
				});

				// Write, i=11588, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11589
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- FileType/11575
				AddDefaultAddressSpaceNodeMethod(11588, "Write", "Write", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11589,  false),
					(37,  78,  false),
					(47,  11575,  true),
				});

				// GetPosition, i=11590, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11591
				//	HasProperty/46 -> OutputArguments/11592
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- FileType/11575
				AddDefaultAddressSpaceNodeMethod(11590, "GetPosition", "GetPosition", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11591,  false),
					(46,  11592,  false),
					(37,  78,  false),
					(47,  11575,  true),
				});

				// SetPosition, i=11593, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11594
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- FileType/11575
				AddDefaultAddressSpaceNodeMethod(11593, "SetPosition", "SetPosition", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11594,  false),
					(37,  78,  false),
					(47,  11575,  true),
				});

				// ExportNamespace, i=11615, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- AddressSpaceFileType/11595
				AddDefaultAddressSpaceNodeMethod(11615, "ExportNamespace", "ExportNamespace", "Updates the file by exporting the server namespace.", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(37,  80,  false),
					(47,  11595,  true),
				});

				// Open, i=11629, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11630
				//	HasProperty/46 -> OutputArguments/11631
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- NamespaceFile/11624
				AddDefaultAddressSpaceNodeMethod(11629, "Open", "Open", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11630,  false),
					(46,  11631,  false),
					(37,  78,  false),
					(47,  11624,  true),
				});

				// Close, i=11632, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11633
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- NamespaceFile/11624
				AddDefaultAddressSpaceNodeMethod(11632, "Close", "Close", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11633,  false),
					(37,  78,  false),
					(47,  11624,  true),
				});

				// Read, i=11634, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11635
				//	HasProperty/46 -> OutputArguments/11636
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- NamespaceFile/11624
				AddDefaultAddressSpaceNodeMethod(11634, "Read", "Read", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11635,  false),
					(46,  11636,  false),
					(37,  78,  false),
					(47,  11624,  true),
				});

				// Write, i=11637, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11638
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- NamespaceFile/11624
				AddDefaultAddressSpaceNodeMethod(11637, "Write", "Write", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11638,  false),
					(37,  78,  false),
					(47,  11624,  true),
				});

				// GetPosition, i=11639, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11640
				//	HasProperty/46 -> OutputArguments/11641
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- NamespaceFile/11624
				AddDefaultAddressSpaceNodeMethod(11639, "GetPosition", "GetPosition", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11640,  false),
					(46,  11641,  false),
					(37,  78,  false),
					(47,  11624,  true),
				});

				// SetPosition, i=11642, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11643
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- NamespaceFile/11624
				AddDefaultAddressSpaceNodeMethod(11642, "SetPosition", "SetPosition", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11643,  false),
					(37,  78,  false),
					(47,  11624,  true),
				});

				// Open, i=11680, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11681
				//	HasProperty/46 -> OutputArguments/11682
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- AddressSpaceFile/11675
				AddDefaultAddressSpaceNodeMethod(11680, "Open", "Open", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11681,  false),
					(46,  11682,  false),
					(37,  78,  false),
					(47,  11675,  true),
				});

				// Close, i=11683, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11684
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- AddressSpaceFile/11675
				AddDefaultAddressSpaceNodeMethod(11683, "Close", "Close", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11684,  false),
					(37,  78,  false),
					(47,  11675,  true),
				});

				// Read, i=11685, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11686
				//	HasProperty/46 -> OutputArguments/11687
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- AddressSpaceFile/11675
				AddDefaultAddressSpaceNodeMethod(11685, "Read", "Read", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11686,  false),
					(46,  11687,  false),
					(37,  78,  false),
					(47,  11675,  true),
				});

				// Write, i=11688, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11689
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- AddressSpaceFile/11675
				AddDefaultAddressSpaceNodeMethod(11688, "Write", "Write", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11689,  false),
					(37,  78,  false),
					(47,  11675,  true),
				});

				// GetPosition, i=11690, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11691
				//	HasProperty/46 -> OutputArguments/11692
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- AddressSpaceFile/11675
				AddDefaultAddressSpaceNodeMethod(11690, "GetPosition", "GetPosition", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11691,  false),
					(46,  11692,  false),
					(37,  78,  false),
					(47,  11675,  true),
				});

				// SetPosition, i=11693, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11694
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- AddressSpaceFile/11675
				AddDefaultAddressSpaceNodeMethod(11693, "SetPosition", "SetPosition", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11694,  false),
					(37,  78,  false),
					(47,  11675,  true),
				});

				// GetMonitoredItems, i=11492, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/11493
				//	HasProperty/46 -> OutputArguments/11494
				//	HasComponent/47 <- Server/2253
				AddDefaultAddressSpaceNodeMethod(11492, "GetMonitoredItems", "GetMonitoredItems", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  11493,  false),
					(46,  11494,  false),
					(47,  2253,  true),
				});

				// Disable, i=9028, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	i=3065/3065 -> AuditConditionEnableEventType/2803
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ConditionType/2782
				AddDefaultAddressSpaceNodeMethod(9028, "Disable", "Disable", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(3065,  2803,  false),
					(37,  78,  false),
					(47,  2782,  true),
				});

				// Enable, i=9027, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	i=3065/3065 -> AuditConditionEnableEventType/2803
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ConditionType/2782
				AddDefaultAddressSpaceNodeMethod(9027, "Enable", "Enable", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(3065,  2803,  false),
					(37,  78,  false),
					(47,  2782,  true),
				});

				// AddComment, i=9029, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/9030
				//	i=3065/3065 -> AuditConditionCommentEventType/2829
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ConditionType/2782
				AddDefaultAddressSpaceNodeMethod(9029, "AddComment", "AddComment", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9030,  false),
					(3065,  2829,  false),
					(37,  78,  false),
					(47,  2782,  true),
				});

				// ConditionRefresh, i=3875, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/3876
				//	i=3065/3065 -> RefreshStartEventType/2787
				//	i=3065/3065 -> RefreshEndEventType/2788
				//	HasComponent/47 <- ConditionType/2782
				AddDefaultAddressSpaceNodeMethod(3875, "ConditionRefresh", "ConditionRefresh", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  3876,  false),
					(3065,  2787,  false),
					(3065,  2788,  false),
					(47,  2782,  true),
				});

				// Respond, i=9069, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/9070
				//	i=3065/3065 -> AuditConditionRespondEventType/8927
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- DialogConditionType/2830
				AddDefaultAddressSpaceNodeMethod(9069, "Respond", "Respond", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9070,  false),
					(3065,  8927,  false),
					(37,  78,  false),
					(47,  2830,  true),
				});

				// Acknowledge, i=9111, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/9112
				//	i=3065/3065 -> AuditConditionAcknowledgeEventType/8944
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- AcknowledgeableConditionType/2881
				AddDefaultAddressSpaceNodeMethod(9111, "Acknowledge", "Acknowledge", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9112,  false),
					(3065,  8944,  false),
					(37,  78,  false),
					(47,  2881,  true),
				});

				// Confirm, i=9113, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/9114
				//	i=3065/3065 -> AuditConditionConfirmEventType/8961
				//	HasModellingRule/37 -> Optional/80
				//	HasComponent/47 <- AcknowledgeableConditionType/2881
				AddDefaultAddressSpaceNodeMethod(9113, "Confirm", "Confirm", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9114,  false),
					(3065,  8961,  false),
					(37,  80,  false),
					(47,  2881,  true),
				});

				// Unshelve, i=9211, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	i=3065/3065 -> AuditConditionShelvingEventType/11093
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ShelvingState/9178
				AddDefaultAddressSpaceNodeMethod(9211, "Unshelve", "Unshelve", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(3065,  11093,  false),
					(37,  78,  false),
					(47,  9178,  true),
				});

				// OneShotShelve, i=9212, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	i=3065/3065 -> AuditConditionShelvingEventType/11093
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ShelvingState/9178
				AddDefaultAddressSpaceNodeMethod(9212, "OneShotShelve", "OneShotShelve", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(3065,  11093,  false),
					(37,  78,  false),
					(47,  9178,  true),
				});


			}
			private void Part17()
			{
				// TimedShelve, i=9213, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/9214
				//	i=3065/3065 -> AuditConditionShelvingEventType/11093
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ShelvingState/9178
				AddDefaultAddressSpaceNodeMethod(9213, "TimedShelve", "TimedShelve", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  9214,  false),
					(3065,  11093,  false),
					(37,  78,  false),
					(47,  9178,  true),
				});

				// Unshelve, i=2947, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	i=53/53 <- TimedShelvedToUnshelved/2940
				//	i=53/53 <- OneShotShelvedToUnshelved/2943
				//	i=3065/3065 -> AuditConditionShelvingEventType/11093
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ShelvedStateMachineType/2929
				AddDefaultAddressSpaceNodeMethod(2947, "Unshelve", "Unshelve", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(53,  2940,  true),
					(53,  2943,  true),
					(3065,  11093,  false),
					(37,  78,  false),
					(47,  2929,  true),
				});

				// OneShotShelve, i=2948, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	i=53/53 <- UnshelvedToOneShotShelved/2936
				//	i=53/53 <- TimedShelvedToOneShotShelved/2942
				//	i=3065/3065 -> AuditConditionShelvingEventType/11093
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ShelvedStateMachineType/2929
				AddDefaultAddressSpaceNodeMethod(2948, "OneShotShelve", "OneShotShelve", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(53,  2936,  true),
					(53,  2942,  true),
					(3065,  11093,  false),
					(37,  78,  false),
					(47,  2929,  true),
				});

				// TimedShelve, i=2949, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasProperty/46 -> InputArguments/2991
				//	i=53/53 <- UnshelvedToTimedShelved/2935
				//	i=53/53 <- OneShotShelvedToTimedShelved/2945
				//	i=3065/3065 -> AuditConditionShelvingEventType/11093
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ShelvedStateMachineType/2929
				AddDefaultAddressSpaceNodeMethod(2949, "TimedShelve", "TimedShelve", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(46,  2991,  false),
					(53,  2935,  true),
					(53,  2945,  true),
					(3065,  11093,  false),
					(37,  78,  false),
					(47,  2929,  true),
				});

				// Start, i=2426, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	i=53/53 <- ReadyToRunning/2410
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeMethod(2426, "Start", "Start", "Causes the Program to transition from the Ready state to the Running state.", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(53,  2410,  true),
					(37,  78,  false),
					(47,  2391,  true),
				});

				// Suspend, i=2427, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	i=53/53 <- RunningToSuspended/2416
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeMethod(2427, "Suspend", "Suspend", "Causes the Program to transition from the Running state to the Suspended state.", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(53,  2416,  true),
					(37,  78,  false),
					(47,  2391,  true),
				});

				// Resume, i=2428, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	i=53/53 <- SuspendedToRunning/2418
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeMethod(2428, "Resume", "Resume", "Causes the Program to transition from the Suspended state to the Running state.", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(53,  2418,  true),
					(37,  78,  false),
					(47,  2391,  true),
				});

				// Halt, i=2429, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	i=53/53 <- RunningToHalted/2412
				//	i=53/53 <- SuspendedToHalted/2420
				//	i=53/53 <- ReadyToHalted/2424
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeMethod(2429, "Halt", "Halt", "Causes the Program to transition from the Ready, Running or Suspended state to the Halted state.", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(53,  2412,  true),
					(53,  2420,  true),
					(53,  2424,  true),
					(37,  78,  false),
					(47,  2391,  true),
				});

				// Reset, i=2430, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	i=53/53 <- HaltedToReady/2408
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- ProgramStateMachineType/2391
				AddDefaultAddressSpaceNodeMethod(2430, "Reset", "Reset", "Causes the Program to transition from the Halted state to the Ready state.", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(53,  2408,  true),
					(37,  78,  false),
					(47,  2391,  true),
				});

				// Lock, i=8922, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- LockType/8921
				AddDefaultAddressSpaceNodeMethod(8922, "Lock", "Lock", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(37,  78,  false),
					(47,  8921,  true),
				});

				// Unlock, i=8923, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasModellingRule/37 -> Mandatory/78
				//	HasComponent/47 <- LockType/8921
				AddDefaultAddressSpaceNodeMethod(8923, "Unlock", "Unlock", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(37,  78,  false),
					(47,  8921,  true),
				});

				// Lock, i=8925, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasComponent/47 <- ServerLock/8924
				AddDefaultAddressSpaceNodeMethod(8925, "Lock", "Lock", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  8924,  true),
				});

				// Unlock, i=8926, TypeGenerator.AddressSpaceGenerator+NodeMethod
				//	HasComponent/47 <- ServerLock/8924
				AddDefaultAddressSpaceNodeMethod(8926, "Unlock", "Unlock", "", 0, 0, false, false, new (uint referenceType, uint target, bool isInverse)[] {
					(47,  8924,  true),
				});


			}


			/// <summary>
			/// Refactored to reduce memory. Instead of instantiating the entire default Address space in one method, call a method per node and split the resulting code in multiple parts
			/// memory spike goes from 276MB in original code to 24MB.
			/// .Net seems to preallocate memory for the objects that will be created in the method (?).
			/// Streamreading the config from a textfile and create node per node would probably even more memory efficient.
			/// </summary>
			private void SetupDefaultAddressSpace()
			{
				Part1();
				Part2();
				Part3();
				Part4();
				Part5();
				Part6();
				Part7();
				Part8();
				Part9();
				Part10();
				Part11();
				Part12();
				Part13();
				Part14();
				Part15();
				Part16();
				Part17();				
			}



		}
	}
}
