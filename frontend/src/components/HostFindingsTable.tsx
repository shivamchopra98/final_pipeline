import { useState } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ChevronLeft, ChevronRight, Search, ExternalLink } from "lucide-react";
import { Separator } from "@/components/ui/separator";

interface Finding {
  hostFindings: string;
  vrrScore: number;
  scannerName: string;
  scannerPluginID: string;
  vulnerabilityName: string;
  scannerReportedSeverity: string;
  scannerSeverity: string;
  description: string;
  status: string;
  port: string;
  protocol: string;
  pluginOutput: string;
  possibleSolutions: string;
  possiblePatches: string;
  ipAddress: string;
  vulnerabilities: string[];
  weaknesses: string[];
  threat: string;
}

interface HostFindingsTableProps {
  data: Finding[];
}

const getSeverityColor = (severity: string) => {
  switch (severity.toLowerCase()) {
    case "critical":
      return "bg-severity-critical text-white";
    case "high":
      return "bg-severity-high text-white";
    case "medium":
      return "bg-severity-medium text-white";
    case "low":
      return "bg-severity-low text-white";
    default:
      return "bg-severity-info text-white";
  }
};

export function HostFindingsTable({ data }: HostFindingsTableProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const itemsPerPage = 10;

  const filteredData = data.filter(
    (item) =>
      item.hostFindings.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.vulnerabilityName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.ipAddress.includes(searchTerm)
  );

  const totalPages = Math.ceil(filteredData.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const paginatedData = filteredData.slice(startIndex, startIndex + itemsPerPage);

  return (
    <div className="bg-card rounded-lg border border-border">
      <div className="p-6 border-b border-border">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-bold text-card-foreground">Host Findings</h2>
          <div className="relative w-64">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search findings..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
              className="pl-10"
            />
          </div>
        </div>
      </div>
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Host</TableHead>
              <TableHead>VRR Score</TableHead>
              <TableHead>Scanner</TableHead>
              <TableHead>Vulnerability</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Port</TableHead>
              <TableHead>IP Address</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {paginatedData.map((finding, index) => (
              <TableRow 
                key={index} 
                className="hover:bg-muted/50 cursor-pointer"
                onClick={() => setSelectedFinding(finding)}
              >
                <TableCell className="font-medium">{finding.hostFindings}</TableCell>
                <TableCell>
                  <Badge variant="outline">{finding.vrrScore}</Badge>
                </TableCell>
                <TableCell>{finding.scannerName}</TableCell>
                <TableCell className="max-w-xs truncate" title={finding.vulnerabilityName}>
                  {finding.vulnerabilityName}
                </TableCell>
                <TableCell>
                  <Badge className={getSeverityColor(finding.scannerSeverity)}>
                    {finding.scannerSeverity}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge variant={finding.status === "Open" ? "destructive" : "secondary"}>
                    {finding.status}
                  </Badge>
                </TableCell>
                <TableCell>
                  {finding.port}/{finding.protocol}
                </TableCell>
                <TableCell className="font-mono text-sm">{finding.ipAddress}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <div className="p-4 border-t border-border flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          Showing {startIndex + 1} to {Math.min(startIndex + itemsPerPage, filteredData.length)} of{" "}
          {filteredData.length} findings
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            disabled={currentPage === 1}
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            disabled={currentPage === totalPages}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Detail Dialog */}
      <Dialog open={!!selectedFinding} onOpenChange={() => setSelectedFinding(null)}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="text-2xl flex items-center gap-3">
              {selectedFinding?.vulnerabilityName}
              <Badge className={getSeverityColor(selectedFinding?.scannerSeverity || "")}>
                {selectedFinding?.scannerSeverity}
              </Badge>
            </DialogTitle>
            <DialogDescription className="text-base">
              {selectedFinding?.description}
            </DialogDescription>
          </DialogHeader>

          {selectedFinding && (
            <div className="space-y-6 mt-4">
              {/* Basic Information */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="font-semibold text-sm text-muted-foreground mb-1">Host</h4>
                  <p className="text-foreground">{selectedFinding.hostFindings}</p>
                </div>
                <div>
                  <h4 className="font-semibold text-sm text-muted-foreground mb-1">IP Address</h4>
                  <p className="font-mono text-sm text-foreground">{selectedFinding.ipAddress}</p>
                </div>
                <div>
                  <h4 className="font-semibold text-sm text-muted-foreground mb-1">VRR Score</h4>
                  <Badge variant="outline" className="text-base">{selectedFinding.vrrScore}</Badge>
                </div>
                <div>
                  <h4 className="font-semibold text-sm text-muted-foreground mb-1">Status</h4>
                  <Badge variant={selectedFinding.status === "Open" ? "destructive" : "secondary"}>
                    {selectedFinding.status}
                  </Badge>
                </div>
              </div>

              <Separator />

              {/* Scanner Information */}
              <div>
                <h3 className="font-bold text-lg mb-3">Scanner Information</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h4 className="font-semibold text-sm text-muted-foreground mb-1">Scanner Name</h4>
                    <p className="text-foreground">{selectedFinding.scannerName}</p>
                  </div>
                  <div>
                    <h4 className="font-semibold text-sm text-muted-foreground mb-1">Plugin ID</h4>
                    <p className="font-mono text-sm text-foreground">{selectedFinding.scannerPluginID}</p>
                  </div>
                  <div>
                    <h4 className="font-semibold text-sm text-muted-foreground mb-1">Port / Protocol</h4>
                    <p className="text-foreground">{selectedFinding.port} / {selectedFinding.protocol}</p>
                  </div>
                  <div>
                    <h4 className="font-semibold text-sm text-muted-foreground mb-1">Reported Severity</h4>
                    <Badge className={getSeverityColor(selectedFinding.scannerReportedSeverity)}>
                      {selectedFinding.scannerReportedSeverity}
                    </Badge>
                  </div>
                </div>
              </div>

              <Separator />

              {/* Plugin Output */}
              <div>
                <h3 className="font-bold text-lg mb-2">Plugin Output</h3>
                <div className="bg-muted p-4 rounded-lg font-mono text-sm text-foreground">
                  {selectedFinding.pluginOutput}
                </div>
              </div>

              <Separator />

              {/* Threat Information */}
              <div>
                <h3 className="font-bold text-lg mb-2">Threat</h3>
                <p className="text-foreground bg-destructive/10 p-4 rounded-lg border border-destructive/20">
                  {selectedFinding.threat}
                </p>
              </div>

              <Separator />

              {/* Solutions and Patches */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="font-bold text-lg mb-2">Possible Solutions</h3>
                  <p className="text-foreground bg-muted p-4 rounded-lg">
                    {selectedFinding.possibleSolutions}
                  </p>
                </div>
                <div>
                  <h3 className="font-bold text-lg mb-2">Possible Patches</h3>
                  <div className="bg-muted p-4 rounded-lg">
                    {selectedFinding.possiblePatches.startsWith('http') ? (
                      <a
                        href={selectedFinding.possiblePatches}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-primary hover:underline flex items-center gap-2"
                      >
                        View Patch Information
                        <ExternalLink className="h-4 w-4" />
                      </a>
                    ) : (
                      <p className="text-foreground">{selectedFinding.possiblePatches}</p>
                    )}
                  </div>
                </div>
              </div>

              <Separator />

              {/* CVEs and Weaknesses */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="font-bold text-lg mb-2">Vulnerabilities (CVEs)</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedFinding.vulnerabilities.map((cve, idx) => (
                      <Badge key={idx} variant="outline" className="font-mono">
                        {cve}
                      </Badge>
                    ))}
                  </div>
                </div>
                <div>
                  <h3 className="font-bold text-lg mb-2">Weaknesses (CWEs)</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedFinding.weaknesses.map((cwe, idx) => (
                      <Badge key={idx} variant="outline" className="text-xs">
                        {cwe}
                      </Badge>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
