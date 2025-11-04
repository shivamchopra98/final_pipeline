import { useState } from "react";
import { Upload as UploadIcon, FileText, X, CheckCircle2, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";

interface UploadedFile {
  name: string;
  size: number;
  type: string;
  content?: string;
  uploadedAt: Date;
}

export default function Upload() {
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);
  const [isDragging, setIsDragging] = useState(false);

  const validateFile = (file: File): boolean => {
    const validTypes = [
      "text/csv",
      "application/csv",
      "text/xml",
      "application/xml",
      "text/plain", // Some systems report CSV as plain text
    ];
    
    const validExtensions = [".csv", ".xml"];
    const fileExtension = file.name.toLowerCase().slice(file.name.lastIndexOf("."));
    
    const isValidType = validTypes.includes(file.type) || validExtensions.includes(fileExtension);
    
    if (!isValidType) {
      toast.error("Invalid file type", {
        description: "Only CSV and XML files are allowed",
      });
      return false;
    }
    
    // Check file size (max 10MB)
    const maxSize = 10 * 1024 * 1024;
    if (file.size > maxSize) {
      toast.error("File too large", {
        description: "Maximum file size is 10MB",
      });
      return false;
    }
    
    return true;
  };

  const handleFileUpload = async (files: FileList | null) => {
    if (!files) return;

    const fileArray = Array.from(files);
    const validFiles = fileArray.filter(validateFile);

    for (const file of validFiles) {
      try {
        const content = await file.text();
        
        const uploadedFile: UploadedFile = {
          name: file.name,
          size: file.size,
          type: file.name.endsWith(".csv") ? "CSV" : "XML",
          content,
          uploadedAt: new Date(),
        };

        setUploadedFiles((prev) => [uploadedFile, ...prev]);
        
        toast.success("File uploaded successfully", {
          description: `${file.name} (${formatFileSize(file.size)})`,
        });
      } catch (error) {
        toast.error("Upload failed", {
          description: `Failed to read ${file.name}`,
        });
      }
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    handleFileUpload(e.dataTransfer.files);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + " " + sizes[i];
  };

  const removeFile = (index: number) => {
    setUploadedFiles((prev) => prev.filter((_, i) => i !== index));
    toast.info("File removed");
  };

  const downloadFile = (file: UploadedFile) => {
    const blob = new Blob([file.content || ""], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = file.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-8 animate-fade-in">
      <div>
        <h1 className="text-3xl font-bold text-foreground mb-2">File Upload</h1>
        <p className="text-muted-foreground">
          Upload CSV and XML files for vulnerability data import
        </p>
      </div>

      {/* Upload Area */}
      <Card
        className={`p-12 border-2 border-dashed transition-all ${
          isDragging
            ? "border-primary bg-primary/5"
            : "border-border hover:border-primary/50"
        }`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
      >
        <div className="flex flex-col items-center justify-center space-y-4">
          <div className="rounded-full bg-primary/10 p-6">
            <UploadIcon className="h-12 w-12 text-primary" />
          </div>
          <div className="text-center">
            <h3 className="text-xl font-semibold text-foreground mb-2">
              Drop files here or click to browse
            </h3>
            <p className="text-muted-foreground mb-4">
              Accepts CSV and XML files up to 10MB
            </p>
          </div>
          <Button
            onClick={() => document.getElementById("file-input")?.click()}
            size="lg"
          >
            Select Files
          </Button>
          <input
            id="file-input"
            type="file"
            accept=".csv,.xml,text/csv,text/xml,application/xml,application/csv"
            multiple
            onChange={(e) => handleFileUpload(e.target.files)}
            className="hidden"
          />
        </div>
      </Card>

      {/* Uploaded Files List */}
      {uploadedFiles.length > 0 && (
        <div>
          <h2 className="text-2xl font-bold text-foreground mb-4">
            Uploaded Files ({uploadedFiles.length})
          </h2>
          <div className="space-y-3">
            {uploadedFiles.map((file, index) => (
              <Card key={index} className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4 flex-1">
                    <div className="rounded-lg bg-primary/10 p-3">
                      <FileText className="h-6 w-6 text-primary" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="font-semibold text-foreground truncate">
                        {file.name}
                      </h4>
                      <div className="flex items-center gap-3 mt-1">
                        <Badge variant="secondary">{file.type}</Badge>
                        <span className="text-sm text-muted-foreground">
                          {formatFileSize(file.size)}
                        </span>
                        <span className="text-sm text-muted-foreground">
                          {file.uploadedAt.toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-5 w-5 text-green-500" />
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => downloadFile(file)}
                    >
                      Download
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => removeFile(index)}
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Info Section */}
      {uploadedFiles.length === 0 && (
        <Card className="p-6 bg-muted/50">
          <div className="flex items-start gap-4">
            <AlertCircle className="h-6 w-6 text-primary mt-1" />
            <div>
              <h3 className="font-semibold text-foreground mb-2">
                Supported File Formats
              </h3>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li className="flex items-center gap-2">
                  <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                  <span>
                    <strong>CSV Files:</strong> Comma-separated vulnerability data exports
                  </span>
                </li>
                <li className="flex items-center gap-2">
                  <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                  <span>
                    <strong>XML Files:</strong> Scanner reports in XML format (Nessus, Qualys, etc.)
                  </span>
                </li>
                <li className="flex items-center gap-2">
                  <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                  <span>Maximum file size: 10MB per file</span>
                </li>
              </ul>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
